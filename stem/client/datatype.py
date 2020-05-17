# Copyright 2018-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Support for `Tor's ORPort protocol
<https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_.

**This module only consists of low level components, and is not intended for
users.** See our :class:`~stem.client.Relay` the API you probably want.

.. versionadded:: 1.7.0

::

  split - splits bytes into substrings

  LinkProtocol - ORPort protocol version.

  Field - Packable and unpackable datatype.
    |- LinkSpecifier - Communication method relays in a circuit.
    |    |- LinkByIPv4 - TLS connection to an IPv4 address.
    |    |- LinkByIPv6 - TLS connection to an IPv6 address.
    |    |- LinkByFingerprint - SHA1 identity fingerprint.
    |    +- LinkByEd25519 - Ed25519 identity fingerprint.
    |
    |- Size - Field of a static size.
    |- Address - Relay address.
    |- Certificate - Relay certificate.
    |
    |- pack - encodes content
    |- unpack - decodes content
    +- pop - decodes content with remainder

  KDF - KDF-TOR derivatived attributes
    +- from_value - parses key material

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

  Certificate purpose. For more information see...

    * `tor-spec.txt <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_ section 4.2
    * `cert-spec.txt <https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt>`_ section A.1
    * `rend-spec-v3.txt <https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt>`_ appendix E

  .. versionchanged:: 1.8.0
     Added the ED25519_SIGNING, LINK_CERT, ED25519_AUTHENTICATE,
     ED25519_IDENTITY, HS_V3_DESC_SIGNING, HS_V3_INTRO_AUTH, NTOR_ONION_KEY,
     and HS_V3_NTOR_ENC certificate types.

  ========================= ===========
  CertType                  Description
  ========================= ===========
  **LINK**                  link key certificate certified by RSA1024 identity
  **IDENTITY**              RSA1024 Identity certificate
  **AUTHENTICATE**          RSA1024 AUTHENTICATE cell link certificate
  **ED25519_SIGNING**       Ed25519 signing key, signed with identity key
  **LINK_CERT**             TLS link certificate, signed with ed25519 signing key
  **ED25519_AUTHENTICATE**  Ed25519 AUTHENTICATE cell key, signed with ed25519 signing key
  **ED25519_IDENTITY**      Ed25519 identity, signed with RSA identity
  **HS_V3_DESC_SIGNING**    hidden service v3 short-term descriptor signing key
  **HS_V3_INTRO_AUTH**      hidden service v3 introduction point authentication key
  **NTOR_ONION_KEY**        ntor onion key cross-certifying ed25519 identity key
  **HS_V3_NTOR_ENC**        hidden service v3 ntor-extra encryption key
  **UNKNOWN**               unrecognized certificate type
  ========================= ===========

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

import binascii
import collections
import hashlib

import stem.client.cell
import stem.util
import stem.util.connection
import stem.util.enum

from typing import Any, Optional, Tuple, Union

ZERO = b'\x00'
HASH_LEN = 20
KEY_LEN = 16


class _IntegerEnum(stem.util.enum.Enum):
  """
  Integer backed enumeration. Enumerations of this type always have an implicit
  **UNKNOWN** value for integer values that lack a mapping.
  """

  def __init__(self, *args: Union[Tuple[str, int], Tuple[str, str, int]]) -> None:
    self._enum_to_int = {}
    self._int_to_enum = {}
    parent_args = []

    for entry in args:
      if len(entry) == 2:
        enum, int_val = entry  # type: ignore
        str_val = enum
      elif len(entry) == 3:
        enum, str_val, int_val = entry  # type: ignore
      else:
        raise ValueError('IntegerEnums can only be constructed with two or three value tuples: %s' % repr(entry))

      self._enum_to_int[str_val] = int_val
      self._int_to_enum[int_val] = str_val
      parent_args.append((enum, str_val))

    parent_args.append(('UNKNOWN', 'UNKNOWN'))
    super(_IntegerEnum, self).__init__(*parent_args)

  def get(self, val: Union[int, str]) -> Tuple[str, int]:
    """
    Provides the (enum, int_value) tuple for a given value.
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
  ('LINK', 1),                  # (tor-spec.txt section 4.2)
  ('IDENTITY', 2),              # (tor-spec.txt section 4.2)
  ('AUTHENTICATE', 3),          # (tor-spec.txt section 4.2)
  ('ED25519_SIGNING', 4),       # (prop220 section 4.2)
  ('LINK_CERT', 5),             # (prop220 section 4.2)
  ('ED25519_AUTHENTICATE', 6),  # (prop220 section 4.2)
  ('ED25519_IDENTITY', 7),      # (prop220 section 4.2)
  ('HS_V3_DESC_SIGNING', 8),    # (rend-spec-v3.txt, "DESC_OUTER" description)
  ('HS_V3_INTRO_AUTH', 9),      # (rend-spec-v3.txt, "auth-key" description)
  ('NTOR_ONION_KEY', 10),       # (dir-spec.txt, "ntor-onion-key-crosscert" description)
  ('HS_V3_NTOR_ENC', 11),       # (rend-spec-v3.txt, "enc-key-cert" description)
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


def split(content: bytes, size: int) -> Tuple[bytes, bytes]:
  """
  Simple split of bytes into two substrings.

  :param content: string to split
  :param size: index to split the string on

  :returns: two value tuple with the split bytes
  """

  return content[:size], content[size:]


class LinkProtocol(int):
  """
  Constants that vary by our link protocol version.

  :var int version: link protocol version
  :var stem.client.datatype.Size circ_id_size: circuit identifier field size
  :var int fixed_cell_length: size of cells with a fixed length
  :var int first_circ_id: When creating circuits we pick an unused identifier
    from a range that's determined by our link protocol.
  """

  def __new__(self, version: int) -> 'stem.client.datatype.LinkProtocol':
    return int.__new__(self, version)  # type: ignore

  def __init__(self, version: int) -> None:
    self.version = version
    self.circ_id_size = Size.LONG if version > 3 else Size.SHORT
    self.first_circ_id = 0x80000000 if version > 3 else 0x01

    cell_header_size = self.circ_id_size.size + 1  # circuit id (2 or 4 bytes) + command (1 byte)
    self.fixed_cell_length = cell_header_size + stem.client.cell.FIXED_PAYLOAD_LEN

  def __hash__(self) -> int:
    # All LinkProtocol attributes can be derived from our version, so that's
    # all we need in our hash. Offsetting by our type so we don't hash conflict
    # with ints.

    return self.version * hash(str(type(self)))

  def __eq__(self, other: Any) -> bool:
    if isinstance(other, int):
      return self.version == other
    elif isinstance(other, LinkProtocol):
      return hash(self) == hash(other)
    else:
      return False

  def __ne__(self, other: Any) -> bool:
    return not self == other

  def __int__(self) -> int:
    return self.version


class Field(object):
  """
  Packable and unpackable datatype.
  """

  def pack(self) -> bytes:
    """
    Encodes field into bytes.

    :returns: **bytes** that can be communicated over Tor's ORPort

    :raises: **ValueError** if incorrect type or size
    """

    raise NotImplementedError('Not yet available')

  @classmethod
  def unpack(cls, packed: bytes) -> 'stem.client.datatype.Field':
    """
    Decodes bytes into a field of this type.

    :param packed: content to decode

    :returns: instance of this class

    :raises: **ValueError** if packed data is malformed
    """

    unpacked, remainder = cls.pop(packed)

    if remainder:
      raise ValueError('%s is the wrong size for a %s field' % (repr(packed), cls.__name__))

    return unpacked

  @staticmethod
  def pop(packed: bytes) -> Tuple[Any, bytes]:
    """
    Decodes bytes as this field type, providing it and the remainder.

    :param packed: content to decode

    :returns: tuple of the form (unpacked, remainder)

    :raises: **ValueError** if packed data is malformed
    """

    raise NotImplementedError('Not yet available')

  def __eq__(self, other: Any) -> bool:
    return hash(self) == hash(other) if isinstance(other, Field) else False

  def __ne__(self, other: Any) -> bool:
    return not self == other


class Size(Field):
  """
  Unsigned `struct.pack format
  <https://docs.python.org/3/library/struct.html#format-characters>` for
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

  CHAR = None  # type: Optional[stem.client.datatype.Size]
  SHORT = None  # type: Optional[stem.client.datatype.Size]
  LONG = None  # type: Optional[stem.client.datatype.Size]
  LONG_LONG = None  # type: Optional[stem.client.datatype.Size]

  def __init__(self, name: str, size: int) -> None:
    self.name = name
    self.size = size

  @staticmethod
  def pop(packed: bytes) -> Tuple[int, bytes]:
    raise NotImplementedError("Use our constant's unpack() and pop() instead")

  def pack(self, content: int) -> bytes:  # type: ignore
    try:
      return content.to_bytes(self.size, 'big')
    except:
      if not isinstance(content, int):
        raise ValueError('Size.pack encodes an integer, but was a %s' % type(content).__name__)
      elif content < 0:
        raise ValueError('Packed values must be positive (attempted to pack %i as a %s)' % (content, self.name))
      else:
        raise

  def unpack(self, packed: bytes) -> int:  # type: ignore
    if self.size != len(packed):
      raise ValueError('%s is the wrong size for a %s field' % (repr(packed), self.name))

    return int.from_bytes(packed, 'big')

  def pop(self, packed: bytes) -> Tuple[int, bytes]:  # type: ignore
    to_unpack, remainder = split(packed, self.size)

    return self.unpack(to_unpack), remainder

  def __hash__(self) -> int:
    return stem.util._hash_attr(self, 'name', 'size', cache = True)


class Address(Field):
  """
  Relay address.

  :var stem.client.AddrType type: address type
  :var int type_int: integer value of the address type
  :var str value: address value
  :var bytes value_bin: encoded address value
  """

  def __init__(self, value: Union[bytes, str], addr_type: Union[int, 'stem.client.datatype.AddrType'] = None) -> None:
    if addr_type is None:
      if stem.util.connection.is_valid_ipv4_address(value):  # type: ignore
        addr_type = AddrType.IPv4
      elif stem.util.connection.is_valid_ipv6_address(value):  # type: ignore
        addr_type = AddrType.IPv6
      else:
        raise ValueError("'%s' isn't an IPv4 or IPv6 address" % stem.util.str_tools._to_unicode(value))

    value_bytes = stem.util.str_tools._to_bytes(value)

    self.value = None  # type: Optional[str]
    self.value_bin = None  # type: Optional[bytes]

    self.type, self.type_int = AddrType.get(addr_type)

    if self.type == AddrType.IPv4:
      if stem.util.connection.is_valid_ipv4_address(value_bytes):  # type: ignore
        self.value = stem.util.str_tools._to_unicode(value_bytes)
        self.value_bin = b''.join([Size.CHAR.pack(int(v)) for v in value_bytes.split(b'.')])
      else:
        if len(value_bytes) != 4:
          raise ValueError('Packed IPv4 addresses should be four bytes, but was: %s' % repr(value))

        self.value = _unpack_ipv4_address(value_bytes)
        self.value_bin = value_bytes
    elif self.type == AddrType.IPv6:
      if stem.util.connection.is_valid_ipv6_address(value_bytes):  # type: ignore
        self.value = stem.util.connection.expand_ipv6_address(value_bytes).lower()  # type: ignore
        self.value_bin = b''.join([Size.SHORT.pack(int(v, 16)) for v in self.value.split(':')])
      else:
        if len(value_bytes) != 16:
          raise ValueError('Packed IPv6 addresses should be sixteen bytes, but was: %s' % repr(value))

        self.value = _unpack_ipv6_address(value_bytes)
        self.value_bin = value_bytes
    else:
      # The spec doesn't really tell us what form to expect errors to be. For
      # now just leaving the value unset so we can fill it in later when we
      # know what would be most useful.

      self.value = None
      self.value_bin = value_bytes

  def pack(self) -> bytes:
    cell = bytearray()
    cell += Size.CHAR.pack(self.type_int)
    cell += Size.CHAR.pack(len(self.value_bin))
    cell += self.value_bin
    return bytes(cell)

  @staticmethod
  def pop(content: bytes) -> Tuple['stem.client.datatype.Address', bytes]:
    addr_type, content = Size.CHAR.pop(content)
    addr_length, content = Size.CHAR.pop(content)

    if len(content) < addr_length:
      raise ValueError('Address specified a payload of %i bytes, but only had %i' % (addr_length, len(content)))

    addr_value, content = split(content, addr_length)

    return Address(addr_value, addr_type), content

  def __hash__(self) -> int:
    return stem.util._hash_attr(self, 'type_int', 'value_bin', cache = True)


class Certificate(Field):
  """
  Relay certificate as defined in tor-spec section 4.2.

  :var stem.client.CertType type: certificate type
  :var int type_int: integer value of the certificate type
  :var bytes value: certificate value
  """

  def __init__(self, cert_type: Union[int, 'stem.client.datatype.CertType'], value: bytes) -> None:
    self.type, self.type_int = CertType.get(cert_type)
    self.value = value

  def pack(self) -> bytes:
    cell = bytearray()
    cell += Size.CHAR.pack(self.type_int)
    cell += Size.SHORT.pack(len(self.value))
    cell += self.value
    return bytes(cell)

  @staticmethod
  def pop(content: bytes) -> Tuple['stem.client.datatype.Certificate', bytes]:
    cert_type, content = Size.CHAR.pop(content)
    cert_size, content = Size.SHORT.pop(content)

    if cert_size > len(content):
      raise ValueError('CERTS cell should have a certificate with %i bytes, but only had %i remaining' % (cert_size, len(content)))

    cert_bytes, content = split(content, cert_size)
    return Certificate(cert_type, cert_bytes), content

  def __hash__(self) -> int:
    return stem.util._hash_attr(self, 'type_int', 'value')


class LinkSpecifier(Field):
  """
  Method of communicating with a circuit's relay. Recognized link specification
  types are an instantiation of a subclass. For more information see the
  `EXTEND cell specification
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt#n975>`_.

  .. versionadded:: 1.8.0

  :var int type: numeric identifier of our type
  :var bytes value: encoded link specification destination
  """

  def __init__(self, link_type: int, value: bytes) -> None:
    self.type = link_type
    self.value = value

  @staticmethod
  def pop(packed: bytes) -> Tuple['stem.client.datatype.LinkSpecifier', bytes]:
    # LSTYPE (Link specifier type)           [1 byte]
    # LSLEN  (Link specifier length)         [1 byte]
    # LSPEC  (Link specifier)                [LSLEN bytes]

    link_type, packed = Size.CHAR.pop(packed)
    value_size, packed = Size.CHAR.pop(packed)

    if value_size > len(packed):
      raise ValueError('Link specifier should have %i bytes, but only had %i remaining' % (value_size, len(packed)))

    value, packed = split(packed, value_size)

    if link_type == 0:
      return LinkByIPv4.unpack(value), packed
    elif link_type == 1:
      return LinkByIPv6.unpack(value), packed
    elif link_type == 2:
      return LinkByFingerprint(value), packed
    elif link_type == 3:
      return LinkByEd25519(value), packed
    else:
      return LinkSpecifier(link_type, value), packed  # unrecognized type

  def pack(self) -> bytes:
    cell = bytearray()
    cell += Size.CHAR.pack(self.type)
    cell += Size.CHAR.pack(len(self.value))
    cell += self.value
    return bytes(cell)


class LinkByIPv4(LinkSpecifier):
  """
  TLS connection to an IPv4 address.

  .. versionadded:: 1.8.0

  :var str address: relay IPv4 address
  :var int port: relay ORPort
  """

  def __init__(self, address: str, port: int) -> None:
    super(LinkByIPv4, self).__init__(0, _pack_ipv4_address(address) + Size.SHORT.pack(port))

    self.address = address
    self.port = port

  @staticmethod
  def unpack(value: bytes) -> 'stem.client.datatype.LinkByIPv4':
    if len(value) != 6:
      raise ValueError('IPv4 link specifiers should be six bytes, but was %i instead: %s' % (len(value), stem.util.str_tools._to_unicode(binascii.hexlify(value))))

    addr, port = split(value, 4)
    return LinkByIPv4(_unpack_ipv4_address(addr), Size.SHORT.unpack(port))


class LinkByIPv6(LinkSpecifier):
  """
  TLS connection to an IPv6 address.

  .. versionadded:: 1.8.0

  :var str address: relay IPv6 address
  :var int port: relay ORPort
  """

  def __init__(self, address: str, port: int) -> None:
    super(LinkByIPv6, self).__init__(1, _pack_ipv6_address(address) + Size.SHORT.pack(port))

    self.address = address
    self.port = port

  @staticmethod
  def unpack(value: bytes) -> 'stem.client.datatype.LinkByIPv6':
    if len(value) != 18:
      raise ValueError('IPv6 link specifiers should be eighteen bytes, but was %i instead: %s' % (len(value), stem.util.str_tools._to_unicode(binascii.hexlify(value))))

    addr, port = split(value, 16)
    return LinkByIPv6(_unpack_ipv6_address(addr), Size.SHORT.unpack(port))


class LinkByFingerprint(LinkSpecifier):
  """
  Connection to a SHA1 identity fingerprint.

  .. versionadded:: 1.8.0

  :var str fingerprint: relay sha1 fingerprint
  """

  def __init__(self, value: bytes) -> None:
    super(LinkByFingerprint, self).__init__(2, value)

    if len(value) != 20:
      raise ValueError('Fingerprint link specifiers should be twenty bytes, but was %i instead: %s' % (len(value), stem.util.str_tools._to_unicode(binascii.hexlify(value))))

    self.fingerprint = stem.util.str_tools._to_unicode(value)


class LinkByEd25519(LinkSpecifier):
  """
  Connection to a Ed25519 identity fingerprint.

  .. versionadded:: 1.8.0

  :var str fingerprint: relay ed25519 fingerprint
  """

  def __init__(self, value: bytes) -> None:
    super(LinkByEd25519, self).__init__(3, value)

    if len(value) != 32:
      raise ValueError('Fingerprint link specifiers should be thirty two bytes, but was %i instead: %s' % (len(value), stem.util.str_tools._to_unicode(binascii.hexlify(value))))

    self.fingerprint = stem.util.str_tools._to_unicode(value)


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
  def from_value(key_material: bytes) -> 'stem.client.datatype.KDF':
    # Derived key material, as per...
    #
    #   K = H(K0 | [00]) | H(K0 | [01]) | H(K0 | [02]) | ...

    derived_key = b''
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


def _pack_ipv4_address(address: str) -> bytes:
  return b''.join([Size.CHAR.pack(int(v)) for v in address.split('.')])


def _unpack_ipv4_address(value: bytes) -> str:
  return '.'.join([str(Size.CHAR.unpack(value[i:i + 1])) for i in range(4)])


def _pack_ipv6_address(address: str) -> bytes:
  return b''.join([Size.SHORT.pack(int(v, 16)) for v in address.split(':')])


def _unpack_ipv6_address(value: bytes) -> str:
  return ':'.join(['%04x' % Size.SHORT.unpack(value[i * 2:(i + 1) * 2]) for i in range(8)])


setattr(Size, 'CHAR', Size('CHAR', 1))
setattr(Size, 'SHORT', Size('SHORT', 2))
setattr(Size, 'LONG', Size('LONG', 4))
setattr(Size, 'LONG_LONG', Size('LONG_LONG', 8))
