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

.. data:: AddrType (enum)

  Form an address takes.

  ===================== ===========
  AddressType           Description
  ===================== ===========
  **HOSTNAME**          relay hostname
  **IPv4**              IPv4 address
  **IPv6**              IPv6 address
  **ERROR_TRANSIENT**   temporarily error retrieving address
  **ERROR_PERMANENT**   permanent error retrieving address
  **UNKNOWN**           unrecognized address type
  ===================== ===========
"""

import collections
import struct

import stem.util.enum

ZERO = '\x00'

__all__ = [
  'cell',
]

AddrType = stem.util.enum.UppercaseEnum(
  'HOSTNAME',
  'IPv4',
  'IPv6',
  'ERROR_TRANSIENT',
  'ERROR_PERMANENT',
  'UNKNOWN',
)

ADDR_INT = {
  0: AddrType.HOSTNAME,
  4: AddrType.IPv4,
  6: AddrType.IPv6,
  16: AddrType.ERROR_TRANSIENT,
  17: AddrType.ERROR_PERMANENT,
}


class Certificate(collections.namedtuple('Certificate', ['type', 'value'])):
  """
  Relay certificate as defined in tor-spec section 4.2. Certificate types
  are...

  ====================  ===========
  Type Value            Description
  ====================  ===========
  1                     Link key certificate certified by RSA1024 identity
  2                     RSA1024 Identity certificate
  3                     RSA1024 AUTHENTICATE cell link certificate
  ====================  ===========

  :var int type: certificate type
  :var bytes value: certificate value
  """


class Address(collections.namedtuple('Address', ['type', 'type_int', 'value', 'value_bin'])):
  """
  Relay address.

  :var stem.client.AddrType type: address type
  :var int type_int: integer value of the address type
  :var unicode value: address value
  :var bytes value_bin: encoded address value
  """

  @staticmethod
  def pack(addr):
    """
    Bytes payload for an address.
    """

    raise NotImplementedError('Not yet available')

  @staticmethod
  def pop(content):
    if not content:
      raise ValueError('Payload empty where an address was expected')
    elif len(content) < 2:
      raise ValueError('Insuffient data for address headers')

    addr_type_int, content = Size.CHAR.pop(content)
    addr_type = ADDR_INT.get(addr_type_int, AddrType.UNKNOWN)
    addr_length, content = Size.CHAR.pop(content)

    if len(content) < addr_length:
      raise ValueError('Address specified a payload of %i bytes, but only had %i' % (addr_length, len(content)))

    # TODO: add support for other address types

    address_bin, content = content[:addr_length], content[addr_length:]
    address = None

    if addr_type == AddrType.IPv4 and len(address_bin) == 4:
      address = '.'.join([str(Size.CHAR.unpack(address_bin[i])) for i in range(4)])

    return Address(addr_type, addr_type_int, address, address_bin), content


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
