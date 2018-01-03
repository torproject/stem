# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for interacting with the ORPort provided by Tor relays. The
:class:`~stem.client.Relay` is a wrapper for :class:`~stem.socket.RelaySocket`,
providing higher level functions in much the same way as our
:class:`~stem.control.Controller` wraps :class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

.. data:: PackType (enum)

  Unsigned `struct.pack format
  <https://docs.python.org/2/library/struct.html#format-characters>` for
  network-order fields.

  ====================  ===========
  PackType              Description
  ====================  ===========
  CHAR                  Unsigned char (1 byte)
  SHORT                 Unsigned short (2 bytes)
  LONG                  Unsigned long (4 bytes)
  LONG_LONG             Unsigned long long (8 bytes)
  ====================  ===========

**Module Overview:**

::

  Relay - Connection with a relay's ORPort.
"""

import struct

from stem.util import enum

PackType = enum.Enum(
  ('CHAR', '!B'),       # 1 byte
  ('SHORT', '!H'),      # 2 bytes
  ('LONG', '!L'),       # 4 bytes
  ('LONG_LONG', '!Q'),  # 8 bytes
)


class Relay(object):
  """
  Connection with a `Tor relay's ORPort
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_.
  """


def serialize_versions(versions):
  """
  Provides the payload for a series of link versions.

  :param list versions: link versions to serialize

  :returns: **bytes** with a payload for these versions
  """

  return b''.join([struct.pack(PackType.SHORT, v) for v in versions])
