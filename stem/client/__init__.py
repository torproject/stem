# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interaction with a Tor relay's ORPort. :class:`~stem.client.Relay` is
a wrapper for :class:`~stem.socket.RelaySocket`, much the same way as
:class:`~stem.control.Controller` provides higher level functions for
:class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

.. data:: Pack (enum)

  Unsigned `struct.pack format
  <https://docs.python.org/2/library/struct.html#format-characters>` for
  network-order fields.

  ====================  ===========
  Pack                  Description
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

from stem.util import enum

ZERO = '\x00'


__all__ = [
  'cell',
]


class Relay(object):
  """
  Connection with a `Tor relay's ORPort
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_.
  """


Pack = enum.Enum(
  ('CHAR', '!B'),       # 1 byte
  ('SHORT', '!H'),      # 2 bytes
  ('LONG', '!L'),       # 4 bytes
  ('LONG_LONG', '!Q'),  # 8 bytes
)
