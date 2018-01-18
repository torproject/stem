# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Interaction with a Tor relay's ORPort. :class:`~stem.client.Relay` is
a wrapper for :class:`~stem.socket.RelaySocket`, much the same way as
:class:`~stem.control.Controller` provides higher level functions for
:class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

::

  split - splits bytes into substrings

  Field - Packable and unpackable datatype.
    |- Size - Field of a static size.
    |- Address - Relay address.
    |- Certificate - Relay certificate.
    |
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

.. data:: CertType (enum)

  Relay certificate type.

  ===================== ===========
  CertType              Description
  ===================== ===========
  **LINK**              link key certificate certified by RSA1024 identity
  **IDENTITY**          RSA1024 Identity certificate
  **AUTHENTICATE**      RSA1024 AUTHENTICATE cell link certificate
  **UNKNOWN**           unrecognized certificate type
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

CertType = stem.util.enum.UppercaseEnum(
  'LINK',
  'IDENTITY',
  'AUTHENTICATE',
  'UNKNOWN',
)

ADDR_INT = {
  0: AddrType.HOSTNAME,
  4: AddrType.IPv4,
  6: AddrType.IPv6,
  16: AddrType.ERROR_TRANSIENT,
  17: AddrType.ERROR_PERMANENT,
}


def split(content, size):
  """
  Simple split of bytes into two substrings.

  :param bytes content: string to split
  :param int size: index to split the string on

  :returns: two value tuple with the split bytes
  """

  return content[:size], content[size:]


class Field(object):
  """
  Packable and unpackable datatype.
  """

  def pack(self):
    """
    Encodes field into bytes.

    :returns: **bytes** that can be communicated over Tor's ORPort

    :raises: **ValueError** if incorrect type or size
    """

    raise NotImplementedError('Not yet available')

  @classmethod
  def unpack(cls, packed):
    """
    Decodes bytes into a field of this type.

    :param bytes packed: content to decode

    :returns: instance of this class

    :raises: **ValueError** if packed data is malformed
    """

    unpacked, remainder = cls.pop(packed)

    if remainder:
      raise ValueError('%s is the wrong size for a %s field' % (repr(packed), cls.__name__))

    return unpacked

  @staticmethod
  def pop(packed):
    """
    Decodes bytes as this field type, providing it and the remainder.

    :param bytes packed: content to decode

    :returns: tuple of the form (unpacked, remainder)

    :raises: **ValueError** if packed data is malformed
    """

    raise NotImplementedError('Not yet available')


class Size(Field):
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

  @staticmethod
  def pop(packed):
    raise NotImplementedError("Use our constant's unpack() and pop() instead")

  def pack(self, content):
    if not isinstance(content, int):
      raise ValueError('Size.pack encodes an integer, but was a %s' % type(content).__name__)

    packed = struct.pack(self.format, content)

    if self.size != len(packed):
      raise ValueError('%s is the wrong size for a %s field' % (repr(packed), self.name))

    return packed

  def unpack(self, packed):
    if self.size != len(packed):
      raise ValueError('%s is the wrong size for a %s field' % (repr(packed), self.name))

    return struct.unpack(self.format, packed)[0]

  def pop(self, packed):
    return self.unpack(packed[:self.size]), packed[self.size:]


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

    address_bin, content = split(content, addr_length)
    address = None

    if addr_type == AddrType.IPv4 and len(address_bin) == 4:
      address = '.'.join([str(Size.CHAR.unpack(address_bin[i])) for i in range(4)])

    return Address(addr_type, addr_type_int, address, address_bin), content


setattr(Size, 'CHAR', Size('CHAR', 1, '!B'))
setattr(Size, 'SHORT', Size('SHORT', 2, '!H'))
setattr(Size, 'LONG', Size('LONG', 4, '!L'))
setattr(Size, 'LONG_LONG', Size('LONG_LONG', 8, '!Q'))
