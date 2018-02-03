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
"""

import stem.client
import stem.client.cell
import stem.socket
import stem.util.connection

DEFAULT_LINK_VERSIONS = (3, 4, 5)


class Relay(object):
  """
  Connection with a Tor relay's ORPort.
  """

  def __init__(self, orport):
    self._orport = orport

  @staticmethod
  def connect(address, port, link_versions = DEFAULT_LINK_VERSIONS):
    """
    Establishes a connection with the given ORPort.

    :param str address: ip address of the relay
    :param int port: ORPort of the relay
    :param tuple link_versions: acceptable link protocol versions

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

    if not stem.util.connection.is_port(port):
      raise ValueError("'%s' isn't a valid port" % port)

    conn = stem.socket.RelaySocket(address, port)
    conn.send(stem.client.cell.VersionsCell(link_versions).pack())
    versions_reply = stem.client.cell.Cell.pop(conn.recv(), 2)[0]

    # TODO: determine the highest common link versions
    # TODO: we should fill in our address, right?
    # TODO: what happens if we skip the NETINFO?

    link_version = 3
    conn.send(stem.client.cell.NetinfoCell(stem.client.Address(address, addr_type), []).pack(link_version))

    # TODO: what if no link protocol versions are acceptable?

    return Relay(conn)
