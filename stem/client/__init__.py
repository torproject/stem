# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interaction with a Tor relay's ORPort. :class:`~stem.client.Relay` is
a wrapper for :class:`~stem.socket.RelaySocket`, much the same way as
:class:`~stem.control.Controller` provides higher level functions for
:class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

::

  Size - Packable and unpackable field size.
    |- pack - encodes content
    |- unpack - decodes content
    +- pop - decodes content with remainder
"""

import struct

ZERO = '\x00'

__all__ = [
  'cell',
]


class Size(object):
  """
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
  """

  def __init__(self, name, size, pack_format):
    self.name = name
    self.size = size
    self.format = pack_format

  def pack(self, content):
    """
    Encodes bytes into a packed field.

    :param bytes content: content to encode

    :raises: **ValueError** if content isn't of the right size
    """

    unpacked = struct.pack(self.format, content)

    if self.size != len(unpacked):
      raise ValueError("'%s' is the wrong size for a %s field" % (unpacked, self.name))

    return unpacked

  def unpack(self, content):
    """
    Decodes packed data into bytes.

    :param bytes content: content to encode

    :raises: **ValueError** if packed data isn't of the right size
    """

    if self.size != len(content):
      raise ValueError("'%s' is the wrong size for a %s field" % (content, self.name))

    return struct.unpack(self.format, content)[0]

  def pop(self, content):
    """
    Decodes the first characters as this data type, providing it and the
    remainder.

    :param bytes content: content to encode

    :raises: **ValueError** if packed data isn't of the right size
    """

    return self.unpack(content[:self.size]), content[self.size:]


setattr(Size, 'CHAR', Size('CHAR', 1, '!B'))
setattr(Size, 'SHORT', Size('SHORT', 2, '!H'))
setattr(Size, 'LONG', Size('LONG', 4, '!L'))
setattr(Size, 'LONG_LONG', Size('LONG_LONG', 8, '!Q'))
