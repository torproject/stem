# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interaction with a Tor relay's ORPort. :class:`~stem.client.Relay` is
a wrapper for :class:`~stem.socket.RelaySocket`, much the same way as
:class:`~stem.control.Controller` provides higher level functions for
:class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

::

  Relay - Connection with a tor relay's ORPort.
    | +- connect - Establishes a connection with a relay.
    |
    |- is_alive - reports if our connection is open or closed
    |- connection_time - time when we last connected or disconnected
    |- close - shuts down our connection
    |
    +- create_circuit - establishes a new circuit

  Circuit - Circuit we've established through a relay.
    |- send - sends a message through this circuit
    +- close - closes this circuit
"""

import hashlib
import threading

import stem
import stem.client.cell
import stem.socket
import stem.util.connection

from stem.client.datatype import ZERO, LinkProtocol, Address, KDF

__all__ = [
  'cell',
  'datatype',
]

DEFAULT_LINK_PROTOCOLS = (3, 4, 5)


class Relay(object):
  """
  Connection with a Tor relay's ORPort.

  :var int link_protocol: link protocol version we established
  """

  def __init__(self, orport, link_protocol):
    self.link_protocol = LinkProtocol(link_protocol)
    self._orport = orport
    self._orport_lock = threading.RLock()
    self._circuits = {}

  @staticmethod
  def connect(address, port, link_protocols = DEFAULT_LINK_PROTOCOLS):
    """
    Establishes a connection with the given ORPort.

    :param str address: ip address of the relay
    :param int port: ORPort of the relay
    :param tuple link_protocols: acceptable link protocol versions

    :raises:
      * **ValueError** if address or port are invalid
      * :class:`stem.SocketError` if we're unable to establish a connection
    """

    relay_addr = Address(address)

    if not stem.util.connection.is_valid_port(port):
      raise ValueError("'%s' isn't a valid port" % port)
    elif not link_protocols:
      raise ValueError("Connection can't be established without a link protocol.")

    try:
      conn = stem.socket.RelaySocket(address, port)
    except stem.SocketError as exc:
      if 'Connection refused' in str(exc):
        raise stem.SocketError("Failed to connect to %s:%i. Maybe it isn't an ORPort?" % (address, port))
      elif 'SSL: ' in str(exc):
        raise stem.SocketError("Failed to SSL authenticate to %s:%i. Maybe it isn't an ORPort?" % (address, port))
      else:
        raise

    # To negotiate our link protocol the first VERSIONS cell is expected to use
    # a circuit ID field size from protocol version 1-3 for backward
    # compatibility...
    #
    #   The first VERSIONS cell, and any cells sent before the
    #   first VERSIONS cell, always have CIRCID_LEN == 2 for backward
    #   compatibility.

    conn.send(stem.client.cell.VersionsCell(link_protocols).pack(2))
    response = conn.recv()

    # Link negotiation ends right away if we lack a common protocol
    # version. (#25139)

    if not response:
      conn.close()
      raise stem.SocketError('Unable to establish a common link protocol with %s:%i' % (address, port))

    versions_reply = stem.client.cell.Cell.pop(response, 2)[0]
    common_protocols = set(link_protocols).intersection(versions_reply.versions)

    if not common_protocols:
      conn.close()
      raise stem.SocketError('Unable to find a common link protocol. We support %s but %s:%i supports %s.' % (', '.join(link_protocols), address, port, ', '.join(versions_reply.versions)))

    # Establishing connections requires sending a NETINFO, but including our
    # address is optional. We can revisit including it when we have a usecase
    # where it would help.

    link_protocol = max(common_protocols)
    conn.send(stem.client.cell.NetinfoCell(relay_addr, []).pack(link_protocol))

    return Relay(conn, link_protocol)

  def is_alive(self):
    """
    Checks if our socket is currently connected. This is a pass-through for our
    socket's :func:`~stem.socket.BaseSocket.is_alive` method.

    :returns: **bool** that's **True** if our socket is connected and **False** otherwise
    """

    return self._orport.is_alive()

  def connection_time(self):
    """
    Provides the unix timestamp for when our socket was either connected or
    disconnected. That is to say, the time we connected if we're currently
    connected and the time we disconnected if we're not connected.

    :returns: **float** for when we last connected or disconnected, zero if
      we've never connected
    """

    return self._orport.connection_time()

  def close(self):
    """
    Closes our socket connection. This is a pass-through for our socket's
    :func:`~stem.socket.BaseSocket.close` method.
    """

    with self._orport_lock:
      return self._orport.close()

  def create_circuit(self):
    """
    Establishes a new circuit.
    """

    with self._orport_lock:
      circ_id = max(self._circuits) + 1 if self._circuits else self.link_protocol.first_circ_id

      create_fast_cell = stem.client.cell.CreateFastCell(circ_id)
      self._orport.send(create_fast_cell.pack(self.link_protocol))

      response = stem.client.cell.Cell.unpack(self._orport.recv(), self.link_protocol)
      created_fast_cells = filter(lambda cell: isinstance(cell, stem.client.cell.CreatedFastCell), response)

      if not created_fast_cells:
        raise ValueError('We should get a CREATED_FAST response from a CREATE_FAST request')

      created_fast_cell = list(created_fast_cells)[0]
      kdf = KDF.from_value(create_fast_cell.key_material + created_fast_cell.key_material)

      if created_fast_cell.derivative_key != kdf.key_hash:
        raise ValueError('Remote failed to prove that it knows our shared key')

      circ = Circuit(self, circ_id, kdf)
      self._circuits[circ.id] = circ

      return circ

  def __iter__(self):
    with self._orport_lock:
      for circ in self._circuits.values():
        yield circ

  def __enter__(self):
    return self

  def __exit__(self, exit_type, value, traceback):
    self.close()


class Circuit(object):
  """
  Circuit through which requests can be made of a `Tor relay's ORPort
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_.

  :var stem.client.Relay relay: relay through which this circuit has been established
  :var int id: circuit id
  :var hashlib.sha1 forward_digest: digest for forward integrity check
  :var hashlib.sha1 backward_digest: digest for backward integrity check
  :var bytes forward_key: forward encryption key
  :var bytes backward_key: backward encryption key
  """

  def __init__(self, relay, circ_id, kdf):
    if not stem.prereq.is_crypto_available():
      raise ImportError('Circuit construction requires the cryptography module')

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    ctr = modes.CTR(ZERO * (algorithms.AES.block_size // 8))

    self.relay = relay
    self.id = circ_id
    self.forward_digest = hashlib.sha1(kdf.forward_digest)
    self.backward_digest = hashlib.sha1(kdf.backward_digest)
    self.forward_key = Cipher(algorithms.AES(kdf.forward_key), ctr, default_backend()).encryptor()
    self.backward_key = Cipher(algorithms.AES(kdf.backward_key), ctr, default_backend()).decryptor()

  def send(self, command, data = '', stream_id = 0):
    """
    Sends a message over the circuit.

    :param stem.client.datatype.RelayCommand command: command to be issued
    :param bytes data: message payload
    :param int stream_id: specific stream this concerns

    :returns: **list** of :class:`~stem.client.cell.RelayCell` responses
    """

    with self.relay._orport_lock:
      # Encrypt and send the cell. Our digest/key only updates if the cell is
      # successfully sent.

      cell = stem.client.cell.RelayCell(self.id, command, data, stream_id = stream_id)
      payload, forward_digest, forward_key = cell.encrypt(self.relay.link_protocol, self.forward_digest, self.forward_key)
      self.relay._orport.send(payload)

      self.forward_digest = forward_digest
      self.forward_key = forward_key

      # Decrypt relay cells received in response. Again, our digest/key only
      # updates when handled successfully.

      reply = self.relay._orport.recv()
      reply_cells = []

      if len(reply) % self.relay.link_protocol.fixed_cell_length != 0:
        raise stem.ProtocolError('Circuit response should be a series of RELAY cells, but received an unexpected size for a response: %i' % len(reply))

      while reply:
        raw_cell, reply = stem.client.cell.Cell.pop(reply, self.relay.link_protocol)

        if raw_cell.VALUE != stem.client.cell.RelayCell.VALUE:
          raise stem.ProtocolError('RELAY cell responses should be %i but was %i' % (stem.client.cell.RelayCell.VALUE, raw_cell.VALUE))
        elif raw_cell.circ_id != self.id:
          raise stem.ProtocolError('Response should be for circuit id %i, not %i' % (self.id, raw_cell.circ_id))

        decrypted_cell, fully_decrypted, new_backward_digest, new_backward_key = raw_cell.decrypt(self.backward_digest, self.backward_key, interpret = True)

        if not fully_decrypted:
          raise stem.ProtocolError('Response for circuit id %i was not fully decrypted, when expected to be' % self.id)

        # Again, if the above raises the digest/key should remain unchanged.

        self.backward_digest = new_backward_digest
        self.backward_key = new_backward_key

        reply_cells.append(decrypted_cell)

      return reply_cells

  def close(self):
    with self.relay._orport_lock:
      self.relay._orport.send(stem.client.cell.DestroyCell(self.id).pack(self.relay.link_protocol))
      del self.relay._circuits[self.id]

  def __enter__(self):
    return self

  def __exit__(self, exit_type, value, traceback):
    self.close()
