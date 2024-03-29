# Copyright 2018-2020, Damian Johnson and The Tor Project
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

from types import TracebackType
from typing import AsyncIterator, Dict, List, Optional, Sequence, Type, Union

from stem.client.cell import (
  CELL_TYPE_SIZE,
  FIXED_PAYLOAD_LEN,
  PAYLOAD_LEN_SIZE,
  Cell,
)

from stem.client.datatype import (
  ZERO,
  Address,
  KDF,
  LinkProtocol,
  RelayCommand,
  split,
)

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

  def __init__(self, orport: stem.socket.RelaySocket, link_protocol: int) -> None:
    self.link_protocol = LinkProtocol(link_protocol)
    self._orport = orport
    self._orport_buffer = b''  # unread bytes
    self._orport_lock = threading.RLock()
    self._circuits = {}  # type: Dict[int, stem.client.Circuit]

  @staticmethod
  async def connect(address: str, port: int, link_protocols: Sequence['stem.client.datatype.LinkProtocol'] = DEFAULT_LINK_PROTOCOLS) -> 'stem.client.Relay':  # type: ignore
    """
    Establishes a connection with the given ORPort.

    :param address: ip address of the relay
    :param port: ORPort of the relay
    :param link_protocols: acceptable link protocol versions

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
      await conn.connect()
    except stem.SocketError as exc:
      if 'Connect call failed' in str(exc):
        raise stem.SocketError("Failed to connect to %s:%i. Maybe it isn't an ORPort?" % (address, port))

      # If not an ORPort (for instance, mistakenly connecting to a ControlPort
      # instead) we'll likely fail during SSL negotiation. This can result
      # in a variety of responses so normalizing what we can...
      #
      #   Debian 9.5:     [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:661)
      #   Ubuntu 16.04:   [SSL: UNKNOWN_PROTOCOL] unknown protocol (_ssl.c:590)
      #   Ubuntu 12.04:   [Errno 1] _ssl.c:504: error:140770FC:SSL routines:SSL23_GET_SERVER_HELLO:unknown protocol

      if 'unknown protocol' in str(exc) or 'wrong version number' in str(exc):
        raise stem.SocketError("Failed to SSL authenticate to %s:%i. Maybe it isn't an ORPort?" % (address, port))

      raise

    # To negotiate our link protocol the first VERSIONS cell is expected to use
    # a circuit ID field size from protocol version 1-3 for backward
    # compatibility...
    #
    #   The first VERSIONS cell, and any cells sent before the
    #   first VERSIONS cell, always have CIRCID_LEN == 2 for backward
    #   compatibility.

    await conn.send(stem.client.cell.VersionsCell(link_protocols).pack(2))  # type: ignore
    response = await conn.recv()

    # Link negotiation ends right away if we lack a common protocol
    # version. (#25139)

    if not response:
      await conn.close()
      raise stem.SocketError('Unable to establish a common link protocol with %s:%i' % (address, port))

    versions_reply = stem.client.cell.Cell.pop(response, 2)[0]  # type: stem.client.cell.VersionsCell # type: ignore
    common_protocols = set(link_protocols).intersection(versions_reply.versions)

    if not common_protocols:
      await conn.close()
      raise stem.SocketError('Unable to find a common link protocol. We support %s but %s:%i supports %s.' % (', '.join(map(str, link_protocols)), address, port, ', '.join(map(str, versions_reply.versions))))

    # Establishing connections requires sending a NETINFO, but including our
    # address is optional. We can revisit including it when we have a usecase
    # where it would help.

    link_protocol = max(common_protocols)
    await conn.send(stem.client.cell.NetinfoCell(relay_addr, []).pack(link_protocol))

    return Relay(conn, link_protocol)

  async def _recv_bytes(self) -> bytes:
    return await self._recv(True)  # type: ignore

  async def _recv(self, raw: bool = False) -> 'stem.client.cell.Cell':
    """
    Reads the next cell from our ORPort. If none is present this blocks
    until one is available.

    :param raw: provides bytes rather than parsing as a cell if **True**

    :returns: next :class:`~stem.client.cell.Cell`
    """

    with self._orport_lock:
      # cells begin with [circ_id][cell_type][...]

      circ_id_size = self.link_protocol.circ_id_size.size

      while len(self._orport_buffer) < (circ_id_size + CELL_TYPE_SIZE.size):
        self._orport_buffer += await self._orport.recv()  # read until we know the cell type

      cell_type = Cell.by_value(CELL_TYPE_SIZE.pop(self._orport_buffer[circ_id_size:])[0])

      if cell_type.IS_FIXED_SIZE:
        cell_size = circ_id_size + CELL_TYPE_SIZE.size + FIXED_PAYLOAD_LEN
      else:
        # variable length, our next field is the payload size

        while len(self._orport_buffer) < (circ_id_size + CELL_TYPE_SIZE.size + FIXED_PAYLOAD_LEN):
          self._orport_buffer += await self._orport.recv()  # read until we know the cell size

        payload_len = PAYLOAD_LEN_SIZE.pop(self._orport_buffer[circ_id_size + CELL_TYPE_SIZE.size:])[0]
        cell_size = circ_id_size + CELL_TYPE_SIZE.size + payload_len

      while len(self._orport_buffer) < cell_size:
        self._orport_buffer += await self._orport.recv()  # read until we have the full cell

      if raw:
        content, self._orport_buffer = split(self._orport_buffer, cell_size)
        return content  # type: ignore
      else:
        cell, self._orport_buffer = Cell.pop(self._orport_buffer, self.link_protocol)
        return cell

  async def _msg(self, cell: 'stem.client.cell.Cell') -> AsyncIterator['stem.client.cell.Cell']:
    """
    Sends a cell on the ORPort and provides the response we receive in reply.

    Unfortunately unlike control sockets, ORPorts don't have generalized rules
    for predictable message IO. With control sockets...

      * Each message we send receives a single reply.
      * We may also receive asynchronous events marked with a 650 status.

    ORPorts by contrast receive variable length cells with differing rules on
    their arrival. As such making a best effort attempt at a send-and-receive
    method in which we do the following...

      * Discard any existing unread data from the socket.
      * Send our request.
      * Await up to a second for a reply.

    It's quite possible this is a stupid approach. If so, patches welcome.

    :param cell: cell to be sent

    :returns: **generator** with the cells received in reply
    """

    # TODO: why is this an iterator?

    await self._orport.recv(timeout = 0)  # discard unread data
    await self._orport.send(cell.pack(self.link_protocol))
    response = await self._orport.recv(timeout = 1)
    yield stem.client.cell.Cell.pop(response, self.link_protocol)[0]

  def is_alive(self) -> bool:
    """
    Checks if our socket is currently connected. This is a pass-through for our
    socket's :func:`~stem.socket.BaseSocket.is_alive` method.

    :returns: **bool** that's **True** if our socket is connected and **False** otherwise
    """

    return self._orport.is_alive()

  def connection_time(self) -> float:
    """
    Provides the unix timestamp for when our socket was either connected or
    disconnected. That is to say, the time we connected if we're currently
    connected and the time we disconnected if we're not connected.

    :returns: **float** for when we last connected or disconnected, zero if
      we've never connected
    """

    return self._orport.connection_time()

  async def close(self) -> None:
    """
    Closes our socket connection. This is a pass-through for our socket's
    :func:`~stem.socket.BaseSocket.close` method.
    """

    with self._orport_lock:
      return await self._orport.close()

  async def create_circuit(self) -> 'stem.client.Circuit':
    """
    Establishes a new circuit.
    """

    with self._orport_lock:
      circ_id = max(self._circuits) + 1 if self._circuits else self.link_protocol.first_circ_id

      create_fast_cell = stem.client.cell.CreateFastCell(circ_id)
      created_fast_cell = None

      async for cell in self._msg(create_fast_cell):
        if isinstance(cell, stem.client.cell.CreatedFastCell):
          created_fast_cell = cell
          break

      if not created_fast_cell:
        raise ValueError('We should get a CREATED_FAST response from a CREATE_FAST request')

      kdf = KDF.from_value(create_fast_cell.key_material + created_fast_cell.key_material)

      if created_fast_cell.derivative_key != kdf.key_hash:
        raise ValueError('Remote failed to prove that it knows our shared key')

      circ = Circuit(self, circ_id, kdf)
      self._circuits[circ.id] = circ

      return circ

  async def __aiter__(self) -> AsyncIterator['stem.client.Circuit']:
    with self._orport_lock:
      for circ in self._circuits.values():
        yield circ

  async def __aenter__(self) -> 'stem.client.Relay':
    return self

  async def __aexit__(self, exit_type: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
    await self.close()


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

  :raises: **ImportError** if the cryptography module is unavailable
  """

  def __init__(self, relay: 'stem.client.Relay', circ_id: int, kdf: 'stem.client.datatype.KDF') -> None:
    try:
      from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
      raise ImportError('Circuit construction requires the cryptography module')

    ctr = modes.CTR(ZERO * (algorithms.AES.block_size // 8))

    self.relay = relay
    self.id = circ_id
    self.forward_digest = hashlib.sha1(kdf.forward_digest)
    self.backward_digest = hashlib.sha1(kdf.backward_digest)
    self.forward_key = Cipher(algorithms.AES(kdf.forward_key), ctr).encryptor()
    self.backward_key = Cipher(algorithms.AES(kdf.backward_key), ctr).decryptor()

  async def directory(self, request: str, stream_id: int = 0) -> bytes:
    """
    Request descriptors from the relay.

    :param request: directory request to make
    :param stream_id: specific stream this concerns

    :returns: **str** with the requested descriptor data
    """

    with self.relay._orport_lock:
      await self._send(RelayCommand.BEGIN_DIR, stream_id = stream_id)
      await self._send(RelayCommand.DATA, request, stream_id = stream_id)

      response = []  # type: List[stem.client.cell.RelayCell]

      while True:
        # Decrypt relay cells received in response. Our digest/key only
        # updates when handled successfully.

        encrypted_cell = await self.relay._recv_bytes()

        decrypted_cell, backward_key, backward_digest = stem.client.cell.RelayCell.decrypt(self.relay.link_protocol, encrypted_cell, self.backward_key, self.backward_digest)

        if self.id != decrypted_cell.circ_id:
          raise stem.ProtocolError('Response should be for circuit id %i, not %i' % (self.id, decrypted_cell.circ_id))

        self.backward_digest = backward_digest
        self.backward_key = backward_key

        if decrypted_cell.command == RelayCommand.END:
          return b''.join([cell.data for cell in response])
        else:
          response.append(decrypted_cell)

  async def _send(self, command: 'stem.client.datatype.RelayCommand', data: Union[bytes, str] = b'', stream_id: int = 0) -> None:
    """
    Sends a message over the circuit.

    :param command: command to be issued
    :param data: message payload
    :param stream_id: specific stream this concerns
    """

    with self.relay._orport_lock:
      # Encrypt and send the cell. Our digest/key only updates if the cell is
      # successfully sent.

      cell = stem.client.cell.RelayCell(self.id, command, data, stream_id = stream_id)
      payload, forward_key, forward_digest = cell.encrypt(self.relay.link_protocol, self.forward_key, self.forward_digest)
      await self.relay._orport.send(payload)

      self.forward_digest = forward_digest
      self.forward_key = forward_key

  async def close(self) -> None:
    with self.relay._orport_lock:
      await self.relay._orport.send(stem.client.cell.DestroyCell(self.id).pack(self.relay.link_protocol))
      del self.relay._circuits[self.id]

  async def __aenter__(self) -> 'stem.client.Circuit':
    return self

  async def __aexit__(self, exit_type: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]) -> None:
    await self.close()
