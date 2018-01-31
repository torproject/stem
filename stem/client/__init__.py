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

  KDF - KDF-TOR derivatived attributes
    +- from_value - parses key material

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

.. data:: RelayCommand (enum)

  Command concerning streams and circuits we've established with a relay.
  Commands have two characteristics...

  * **forward/backward**: **forward** commands are issued from the orgin,
    whereas **backward** come from the relay

  * **stream/circuit**: **steam** commands concern an individual steam, whereas
    **circuit** concern the entire circuit we've established with a relay

  ===================== ===========
  RelayCommand          Description
  ===================== ===========
  **BEGIN**             begin a stream (**forward**, **stream**)
  **DATA**              transmit data (**forward/backward**, **stream**)
  **END**               end a stream (**forward/backward**, **stream**)
  **CONNECTED**         BEGIN reply (**backward**, **stream**)
  **SENDME**            ready to accept more cells (**forward/backward**, **stream/circuit**)
  **EXTEND**            extend the circuit through another relay (**forward**, **circuit**)
  **EXTENDED**          EXTEND reply (**backward**, **circuit**)
  **TRUNCATE**          remove last circuit hop (**forward**, **circuit**)
  **TRUNCATED**         TRUNCATE reply (**backward**, **circuit**)
  **DROP**              ignorable no-op (**forward/backward**, **circuit**)
  **RESOLVE**           request DNS resolution (**forward**, **stream**)
  **RESOLVED**          RESOLVE reply (**backward**, **stream**)
  **BEGIN_DIR**         request descriptor (**forward**, **steam**)
  **EXTEND2**           ntor EXTEND request (**forward**, **circuit**)
  **EXTENDED2**         EXTEND2 reply (**backward**, **circuit**)
  **UNKNOWN**           unrecognized command
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

.. data:: CloseReason (enum)

  Reason a relay is closed.

  ===================== ===========
  CloseReason           Description
  ===================== ===========
  **NONE**              no reason given
  **PROTOCOL**          tor protocol violation
  **INTERNAL**          internal error
  **REQUESTED**         client sent a TRUNCATE command
  **HIBERNATING**       relay suspended, trying to save bandwidth
  **RESOURCELIMIT**     out of memory, sockets, or circuit IDs
  **CONNECTFAILED**     unable to reach relay
  **OR_IDENTITY**       connected, but its OR identity was not as expected
  **OR_CONN_CLOSED**    connection that was carrying this circuit died
  **FINISHED**          circuit has expired for being dirty or old
  **TIMEOUT**           circuit construction took too long
  **DESTROYED**         circuit was destroyed without a client TRUNCATE
  **NOSUCHSERVICE**     request was for an unknown hidden service
  **UNKNOWN**           unrecognized reason
  ===================== ===========
"""

import collections
import hashlib
import io
import struct

import stem.util.connection
import stem.util.enum

from stem.util import _hash_attr

ZERO = '\x00'
HASH_LEN = 20
KEY_LEN = 16

__all__ = [
  'cell',
]


class _IntegerEnum(stem.util.enum.Enum):
  """
  Integer backed enumeration. Enumerations of this type always have an implicit
  **UNKNOWN** value for integer values that lack a mapping.
  """

  def __init__(self, *args):
    self._enum_to_int = {}
    self._int_to_enum = {}
    parent_args = []

    for entry in args:
      if len(entry) == 2:
        enum, int_val = entry
        str_val = enum
      elif len(entry) == 3:
        enum, str_val, int_val = entry
      else:
        raise ValueError('IntegerEnums can only be constructed with two or three value tuples: %s' % repr(entry))

      self._enum_to_int[str_val] = int_val
      self._int_to_enum[int_val] = str_val
      parent_args.append((enum, str_val))

    parent_args.append(('UNKNOWN', 'UNKNOWN'))
    super(_IntegerEnum, self).__init__(*parent_args)

  def get(self, val):
    """
    Privides the (enum, int_value) tuple for a given value.
    """

    if isinstance(val, int):
      return self._int_to_enum.get(val, self.UNKNOWN), val
    elif val in self:
      return val, self._enum_to_int.get(val, val)
    else:
      raise ValueError("Invalid enumeration '%s', options are %s" % (val, ', '.join(self)))


AddrType = _IntegerEnum(
  ('HOSTNAME', 0),
  ('IPv4', 4),
  ('IPv6', 6),
  ('ERROR_TRANSIENT', 16),
  ('ERROR_PERMANENT', 17),
)

RelayCommand = _IntegerEnum(
  ('BEGIN', 'RELAY_BEGIN', 1),
  ('DATA', 'RELAY_DATA', 2),
  ('END', 'RELAY_END', 3),
  ('CONNECTED', 'RELAY_CONNECTED', 4),
  ('SENDME', 'RELAY_SENDME', 5),
  ('EXTEND', 'RELAY_EXTEND', 6),
  ('EXTENDED', 'RELAY_EXTENDED', 7),
  ('TRUNCATE', 'RELAY_TRUNCATE', 8),
  ('TRUNCATED', 'RELAY_TRUNCATED', 9),
  ('DROP', 'RELAY_DROP', 10),
  ('RESOLVE', 'RELAY_RESOLVE', 11),
  ('RESOLVED', 'RELAY_RESOLVED', 12),
  ('BEGIN_DIR', 'RELAY_BEGIN_DIR', 13),
  ('EXTEND2', 'RELAY_EXTEND2', 14),
  ('EXTENDED2', 'RELAY_EXTENDED2', 15),
)

CertType = _IntegerEnum(
  ('LINK', 1),
  ('IDENTITY', 2),
  ('AUTHENTICATE', 3),
)

CloseReason = _IntegerEnum(
  ('NONE', 0),
  ('PROTOCOL', 1),
  ('INTERNAL', 2),
  ('REQUESTED', 3),
  ('HIBERNATING', 4),
  ('RESOURCELIMIT', 5),
  ('CONNECTFAILED', 6),
  ('OR_IDENTITY', 7),
  ('OR_CONN_CLOSED', 8),
  ('FINISHED', 9),
  ('TIMEOUT', 10),
  ('DESTROYED', 11),
  ('NOSUCHSERVICE', 12),
)

STREAM_ID_REQUIRED = (
  RelayCommand.BEGIN,
  RelayCommand.DATA,
  RelayCommand.END,
  RelayCommand.CONNECTED,
  RelayCommand.RESOLVE,
  RelayCommand.RESOLVED,
  RelayCommand.BEGIN_DIR,
)

STREAM_ID_DISALLOWED = (
  RelayCommand.EXTEND,
  RelayCommand.EXTENDED,
  RelayCommand.TRUNCATE,
  RelayCommand.TRUNCATED,
  RelayCommand.DROP,
  RelayCommand.EXTEND2,
  RelayCommand.EXTENDED2,
)


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

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Field) else False

  def __ne__(self, other):
    return not self == other


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


class Address(Field):
  """
  Relay address.

  :var stem.client.AddrType type: address type
  :var int type_int: integer value of the address type
  :var unicode value: address value
  :var bytes value_bin: encoded address value
  """

  def __init__(self, value, addr_type = None):
    if addr_type is None:
      if stem.util.connection.is_valid_ipv4_address(value):
        addr_type = AddrType.IPv4
      elif stem.util.connection.is_valid_ipv6_address(value):
        addr_type = AddrType.IPv6
      else:
        raise ValueError('Address type is required unless an IPv4 or IPv6 address')

    self.type, self.type_int = AddrType.get(addr_type)

    if self.type == AddrType.IPv4:
      if stem.util.connection.is_valid_ipv4_address(value):
        self.value = value
        self.value_bin = ''.join([Size.CHAR.pack(int(v)) for v in value.split('.')])
      else:
        if len(value) != 4:
          raise ValueError('Packed IPv4 addresses should be four bytes, but was: %s' % repr(value))

        self.value = '.'.join([str(Size.CHAR.unpack(value[i])) for i in range(4)])
        self.value_bin = value
    elif self.type == AddrType.IPv6:
      if stem.util.connection.is_valid_ipv6_address(value):
        self.value = stem.util.connection.expand_ipv6_address(value).lower()
        self.value_bin = ''.join([Size.SHORT.pack(int(v, 16)) for v in self.value.split(':')])
      else:
        if len(value) != 16:
          raise ValueError('Packed IPv6 addresses should be sixteen bytes, but was: %s' % repr(value))

        self.value = ':'.join(['%04x' % Size.SHORT.unpack(value[i * 2:(i + 1) * 2]) for i in range(8)])
        self.value_bin = value
    else:
      # The spec doesn't really tell us what form to expect errors to be. For
      # now just leaving the value unset so we can fill it in later when we
      # know what would be most useful.

      self.value = None
      self.value_bin = value

  def pack(self):
    cell = io.BytesIO()
    cell.write(Size.CHAR.pack(self.type_int))
    cell.write(Size.CHAR.pack(len(self.value_bin)))
    cell.write(self.value_bin)
    return cell.getvalue()

  @staticmethod
  def pop(content):
    if not content:
      raise ValueError('Payload empty where an address was expected')
    elif len(content) < 2:
      raise ValueError('Insuffient data for address headers')

    addr_type, content = Size.CHAR.pop(content)
    addr_length, content = Size.CHAR.pop(content)

    if len(content) < addr_length:
      raise ValueError('Address specified a payload of %i bytes, but only had %i' % (addr_length, len(content)))

    addr_value, content = split(content, addr_length)

    return Address(addr_value, addr_type), content

  def __hash__(self):
    return _hash_attr(self, 'type_int', 'value_bin')


class Certificate(Field):
  """
  Relay certificate as defined in tor-spec section 4.2.

  :var stem.client.CertType type: certificate type
  :var int type_int: integer value of the certificate type
  :var bytes value: certificate value
  """

  def __init__(self, cert_type, value):
    self.type, self.type_int = CertType.get(cert_type)
    self.value = value

  def pack(self):
    cell = io.BytesIO()
    cell.write(Size.CHAR.pack(self.type_int))
    cell.write(Size.SHORT.pack(len(self.value)))
    cell.write(self.value)
    return cell.getvalue()

  @staticmethod
  def pop(content):
    cert_type, content = Size.CHAR.pop(content)
    cert_size, content = Size.SHORT.pop(content)

    if cert_size > len(content):
      raise ValueError('CERTS cell should have a certificate with %i bytes, but only had %i remaining' % (cert_size, len(content)))

    cert_bytes, content = split(content, cert_size)
    return Certificate(cert_type, cert_bytes), content

  def __hash__(self):
    return _hash_attr(self, 'type_int', 'value')


class KDF(collections.namedtuple('KDF', ['key_hash', 'forward_digest', 'backward_digest', 'forward_key', 'backward_key'])):
  """
  Computed KDF-TOR derived values for TAP, CREATE_FAST handshakes, and hidden
  service protocols as defined tor-spec section 5.2.1.

  :var bytes key_hash: hash that proves knowledge of our shared key
  :var bytes forward_digest: forward digest hash seed
  :var bytes backward_digest: backward digest hash seed
  :var bytes forward_key: forward encryption key
  :var bytes backward_key: backward encryption key
  """

  @staticmethod
  def from_value(key_material):
    # Derived key material, as per...
    #
    #   K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...

    derived_key = ''
    counter = 0

    while len(derived_key) < KEY_LEN * 2 + HASH_LEN * 3:
      derived_key += hashlib.sha1(key_material + Size.CHAR.pack(counter)).digest()
      counter += 1

    key_hash, derived_key = split(derived_key, HASH_LEN)
    forward_digest, derived_key = split(derived_key, HASH_LEN)
    backward_digest, derived_key = split(derived_key, HASH_LEN)
    forward_key, derived_key = split(derived_key, KEY_LEN)
    backward_key, derived_key = split(derived_key, KEY_LEN)

    return KDF(key_hash, forward_digest, backward_digest, forward_key, backward_key)


setattr(Size, 'CHAR', Size('CHAR', 1, '!B'))
setattr(Size, 'SHORT', Size('SHORT', 2, '!H'))
setattr(Size, 'LONG', Size('LONG', 4, '!L'))
setattr(Size, 'LONG_LONG', Size('LONG_LONG', 8, '!Q'))
