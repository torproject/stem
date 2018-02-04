# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interaction with a Tor relay's ORPort. :class:`~stem.relay.Relay` is
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
    +- close - shuts down our connection
"""

import stem
import stem.client
import stem.client.cell
import stem.socket
import stem.util.connection

DEFAULT_LINK_PROTOCOLS = (3, 4, 5)


class Relay(object):
  """
  Connection with a Tor relay's ORPort.

  :var int link_protocol: link protocol version we established
  """

  def __init__(self, orport, link_protocol):
    self.link_protocol = link_protocol
    self._orport = orport

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

    if stem.util.connection.is_valid_ipv4_address(address):
      addr_type = stem.client.AddrType.IPv4
    elif stem.util.connection.is_valid_ipv6_address(address):
      addr_type = stem.client.AddrType.IPv6
    else:
      raise ValueError("'%s' isn't an IPv4 or IPv6 address" % address)

    if not stem.util.connection.is_valid_port(port):
      raise ValueError("'%s' isn't a valid port" % port)
    elif not link_protocols:
      raise ValueError("Connection can't be established without a link protocol.")

    try:
      conn = stem.socket.RelaySocket(address, port)
    except stem.SocketError as exc:
      if 'Connection refused' in str(exc):
        raise stem.SocketError("Failed to connect to %s:%i. Maybe it isn't an ORPort?" % (address, port))
      elif 'SSL: UNKNOWN_PROTOCOL' in str(exc):
        raise stem.SocketError("Failed to SSL authenticate to %s:%i. Maybe it isn't an ORPort?" % (address, port))
      else:
        raise

    conn.send(stem.client.cell.VersionsCell(link_protocols).pack())
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

    # TODO: we should fill in our address, right?
    # TODO: what happens if we skip the NETINFO?

    link_protocol = max(common_protocols)
    conn.send(stem.client.cell.NetinfoCell(stem.client.Address(address, addr_type), []).pack(link_protocol))

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

    return self._orport.close()

  def __enter__(self):
    return self

  def __exit__(self, exit_type, value, traceback):
    self.close()
