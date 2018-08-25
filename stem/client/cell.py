# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Messages communicated over a Tor relay's ORPort.

.. versionadded:: 1.7.0

**Module Overview:**

::

  Cell - Base class for ORPort messages.
    |- CircuitCell - Circuit management.
    |  |- CreateCell - Create a circuit.              (section 5.1)
    |  |- CreatedCell - Acknowledge create.           (section 5.1)
    |  |- RelayCell - End-to-end data.                (section 6.1)
    |  |- DestroyCell - Stop using a circuit.         (section 5.4)
    |  |- CreateFastCell - Create a circuit, no PK.   (section 5.1)
    |  |- CreatedFastCell - Circuit created, no PK.   (section 5.1)
    |  |- RelayEarlyCell - End-to-end data; limited.  (section 5.6)
    |  |- Create2Cell - Extended CREATE cell.         (section 5.1)
    |  +- Created2Cell - Extended CREATED cell.       (section 5.1)
    |
    |- PaddingCell - Padding negotiation.             (section 7.2)
    |- VersionsCell - Negotiate proto version.        (section 4)
    |- NetinfoCell - Time and address info.           (section 4.5)
    |- PaddingNegotiateCell - Padding negotiation.    (section 7.2)
    |- VPaddingCell - Variable-length padding.        (section 7.2)
    |- CertsCell - Relay certificates.                (section 4.2)
    |- AuthChallengeCell - Challenge value.           (section 4.3)
    |- AuthenticateCell - Client authentication.      (section 4.5)
    |- AuthorizeCell - Client authorization.          (not yet used)
    |
    |- pack - encodes cell into bytes
    |- unpack - decodes series of cells
    +- pop - decodes cell with remainder
"""

import copy
import datetime
import inspect
import os
import sys

import stem.util

from stem import UNDEFINED
from stem.client.datatype import HASH_LEN, ZERO, LinkProtocol, Address, Certificate, CloseReason, RelayCommand, Size, split
from stem.util import datetime_to_unix, str_tools

FIXED_PAYLOAD_LEN = 509  # PAYLOAD_LEN, per tor-spec section 0.2
AUTH_CHALLENGE_SIZE = 32
RELAY_DIGEST_SIZE = Size.LONG

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


class Cell(object):
  """
  Metadata for ORPort cells.

  Unused padding are **not** used in equality checks or hashing. If two cells
  differ only in their *unused* attribute they are functionally equal.

  The following cell types explicitly don't have *unused* content:
    * PaddingCell (we consider all content part of payload)
    * VersionsCell (all content is unpacked and treated as a version specification)
    * VPaddingCell (we consider all content part of payload)

  :var bytes unused: unused filler that padded the cell to the expected size
  """

  NAME = 'UNKNOWN'
  VALUE = -1
  IS_FIXED_SIZE = False

  def __init__(self, unused = b''):
    super(Cell, self).__init__()
    self.unused = unused

  @staticmethod
  def by_name(name):
    """
    Provides cell attributes by its name.

    :param str name: cell command to fetch

    :raises: **ValueError** if cell type is invalid
    """

    for _, cls in inspect.getmembers(sys.modules[__name__]):
      if name == getattr(cls, 'NAME', UNDEFINED) and not getattr(cls, 'CANNOT_DIRECTLY_UNPACK', False):
        return cls

    raise ValueError("'%s' isn't a valid cell type" % name)

  @staticmethod
  def by_value(value):
    """
    Provides cell attributes by its value.

    :param int value: cell value to fetch

    :raises: **ValueError** if cell type is invalid
    """

    for _, cls in inspect.getmembers(sys.modules[__name__]):
      if value == getattr(cls, 'VALUE', UNDEFINED) and not getattr(cls, 'CANNOT_DIRECTLY_UNPACK', False):
        return cls

    raise ValueError("'%s' isn't a valid cell value" % value)

  def pack(self, link_protocol):
    raise NotImplementedError('Packing not yet implemented for %s cells' % type(self).NAME)

  @staticmethod
  def unpack(content, link_protocol):
    """
    Unpacks all cells from a response.

    :param bytes content: payload to decode
    :param int link_protocol: link protocol version

    :returns: :class:`~stem.client.cell.Cell` generator

    :raises:
      * ValueError if content is malformed
      * NotImplementedError if unable to unpack any of the cell types
    """

    while content:
      cell, content = Cell.pop(content, link_protocol)
      yield cell

  @staticmethod
  def pop(content, link_protocol):
    """
    Unpacks the first cell.

    :param bytes content: payload to decode
    :param int link_protocol: link protocol version

    :returns: (:class:`~stem.client.cell.Cell`, remainder) tuple

    :raises:
      * ValueError if content is malformed
      * NotImplementedError if unable to unpack this cell type
    """

    link_protocol = LinkProtocol(link_protocol)

    circ_id, content = link_protocol.circ_id_size.pop(content)
    command, content = Size.CHAR.pop(content)
    cls = Cell.by_value(command)

    if cls.IS_FIXED_SIZE:
      payload_len = FIXED_PAYLOAD_LEN
    else:
      payload_len, content = Size.SHORT.pop(content)

    if len(content) < payload_len:
      raise ValueError('%s cell should have a payload of %i bytes, but only had %i' % (cls.NAME, payload_len, len(content)))

    payload, content = split(content, payload_len)
    return cls._unpack(payload, circ_id, link_protocol), content

  @classmethod
  def _pack(cls, link_protocol, payload, unused = b'', circ_id = None):
    """
    Provides bytes that can be used on the wire for these cell attributes.
    Format of a properly packed cell depends on if it's fixed or variable
    sized...

    ::

      Fixed:    [ CircuitID ][ Command ][ Payload ][ Padding ]
      Variable: [ CircuitID ][ Command ][ Size ][ Payload ]

    :param str name: cell command
    :param int link_protocol: link protocol version
    :param bytes payload: cell payload
    :param int circ_id: circuit id, if a CircuitCell

    :returns: **bytes** with the encoded payload

    :raises: **ValueError** if cell type invalid or payload makes cell too large
    """

    if issubclass(cls, CircuitCell):
      if circ_id is None:
        raise ValueError('%s cells require a circuit identifier' % cls.NAME)
      elif circ_id < 1:
        raise ValueError('Circuit identifiers must a positive integer, not %s' % circ_id)
    else:
      if circ_id is not None:
        raise ValueError('%s cells should not specify a circuit identifier' % cls.NAME)

      circ_id = 0  # cell doesn't concern a circuit, default field to zero

    link_protocol = LinkProtocol(link_protocol)

    cell = bytearray()
    cell += link_protocol.circ_id_size.pack(circ_id)
    cell += Size.CHAR.pack(cls.VALUE)
    cell += b'' if cls.IS_FIXED_SIZE else Size.SHORT.pack(len(payload) + len(unused))
    cell += payload

    # include the unused portion (typically from unpacking)
    cell += unused

    # pad fixed sized cells to the required length

    if cls.IS_FIXED_SIZE:
      if len(cell) > link_protocol.fixed_cell_length:
        raise ValueError('Cell of type %s is too large (%i bytes), must not be more than %i. Check payload size (was %i bytes)' % (cls.NAME, len(cell), link_protocol.fixed_cell_length, len(payload)))

      cell += ZERO * (link_protocol.fixed_cell_length - len(cell))

    return bytes(cell)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    """
    Subclass implementation for unpacking cell content.

    :param bytes content: payload to decode
    :param stem.client.datatype.LinkProtocol link_protocol: link protocol version
    :param int circ_id: circuit id cell is for

    :returns: instance of this cell type

    :raises: **ValueError** if content is malformed
    """

    raise NotImplementedError('Unpacking not yet implemented for %s cells' % cls.NAME)

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Cell) else False

  def __ne__(self, other):
    return not self == other


class CircuitCell(Cell):
  """
  Cell concerning circuits.

  :var int circ_id: circuit id
  """

  def __init__(self, circ_id, unused = b''):
    super(CircuitCell, self).__init__(unused)
    self.circ_id = circ_id


class PaddingCell(Cell):
  """
  Randomized content to either keep activity going on a circuit.

  :var bytes payload: randomized payload
  """

  NAME = 'PADDING'
  VALUE = 0
  IS_FIXED_SIZE = True

  def __init__(self, payload = None):
    if not payload:
      payload = os.urandom(FIXED_PAYLOAD_LEN)
    elif len(payload) != FIXED_PAYLOAD_LEN:
      raise ValueError('Padding payload should be %i bytes, but was %i' % (FIXED_PAYLOAD_LEN, len(payload)))

    super(PaddingCell, self).__init__()
    self.payload = payload

  def pack(self, link_protocol):
    return PaddingCell._pack(link_protocol, self.payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    return PaddingCell(content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'payload', cache = True)


class CreateCell(CircuitCell):
  NAME = 'CREATE'
  VALUE = 1
  IS_FIXED_SIZE = True

  def __init__(self):
    super(CreateCell, self).__init__()  # TODO: implement


class CreatedCell(CircuitCell):
  NAME = 'CREATED'
  VALUE = 2
  IS_FIXED_SIZE = True

  def __init__(self):
    super(CreatedCell, self).__init__()  # TODO: implement


class BaseRelayCell(CircuitCell):
  """
  Cell whose subclasses are relayed over circuits.

  :var bytes payload: raw payload, quite possibly encrypted
  """

  NAME = 'INTERNAL_BASE_RELAY'  # defined for error/other strings
  IS_FIXED_SIZE = True  # all relay cells are fixed-size

  # other attributes are deferred to subclasses, since this class cannot be directly unpacked

  def __init__(self, circ_id, payload):
    if not payload:
      raise ValueError('Relay cells require a payload')
    if len(payload) != FIXED_PAYLOAD_LEN:
      raise ValueError('Payload should be %i bytes, but was %i' % (FIXED_PAYLOAD_LEN, len(payload)))

    super(BaseRelayCell, self).__init__(circ_id, unused = b'')
    self.payload = payload

  def pack(self, link_protocol):
    # unlike everywhere else, we actually want to use the subclass type, NOT *this* class
    return type(self)._pack(link_protocol, self.payload, circ_id = self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    # unlike everywhere else, we actually want to use the subclass type, NOT *this* class
    return cls(circ_id, content)

  def check_recognized_field(self):
    """
    Checks the 'recognized' field of the cell payload, which indicates whether
    it is **probably** fully decrypted.

    :returns: **bool** indicating whether the 'recognized' field indicates
      likely decryption. Per the spec:
        * **False** guarantees the cell *not* to be fully decrypted.
        * **True** does *not* guarantee the cell to be fully decrypted, and it
          must be checked further. See also
          :func:`~stem.client.cell.BaseRelayCell.check_digest`
    """

    _, recognized_from_cell, _, _, _, _, _ = AlternateRelayCell._unpack_payload(self.payload)
    return recognized_from_cell == 0

  def check_digest(self, digest):
    """
    Calculates the running digest of the cell payload per the spec, returning
    whether the cell's unpacked digest matched, along with the updated digest
    if so.

    :param HASH digest: running digest held with the relay

    :returns: (digest_matches, digest) tuple of object copies updated as follows:
      * digest_matches: **bool** indicating whether the digest matches
      * digest: updated via digest.update(payload), if the digest matches;
        otherwise a copy of the original

    :raises: **ValueError** if payload is the wrong size
    """

    command, recognized, stream_id, digest_from_cell, data_len, data, unused = AlternateRelayCell._unpack_payload(self.payload)

    # running digest is calculated using a zero'd digest field in the payload
    prepared_payload = AlternateRelayCell._pack_payload(command, recognized, stream_id, 0, data_len, data, unused, pad_remainder = False)

    if len(prepared_payload) != FIXED_PAYLOAD_LEN:
      # this should never fail
      # if it did, it indicates a programming error either within stem.client.cell or a consumer
      raise ValueError('Payload should be %i bytes, but was %i' % (FIXED_PAYLOAD_LEN, len(prepared_payload)))

    new_digest = digest.copy()
    new_digest.update(prepared_payload)

    digest_matches = (AlternateRelayCell._coerce_digest(new_digest) == digest_from_cell)

    # only return the new_digest if the digest check passed
    # even if not, return a copy of the original
    # this allows a consumer to always assume the returned digest is a different object
    digest_to_return = new_digest if digest_matches else digest.copy()

    return digest_matches, digest_to_return

  def interpret_cell(self):
    """
    Interprets the cell payload, returning a new
    :class:`~stem.client.cell.RelayCell` class or subclass according to its
    contents.

    This method should only be used on fully decrypted cells, but that
    responsibility is relegated to the caller.

    Furthermore, this interpretation may cause an exception for a NYI relay
    command, a malformed cell, or some other reason.

    :returns: :class:`~stem.client.cell.RelayCell` class or subclass
    """

    # TODO: this mapping is quite hardcoded right now, but probably needs to be
    # completely reworked once the Cell class hierarchy is better fleshed out.
    #
    # (It doesn't really make sense to have anything beyond this hack in the
    # interim.)
    #
    # At that time, it would probably be modeled after Cell.by_value(), albeit
    # specialized for the multiple types of RELAY / RELAY_EARLY cells.

    relay_cells_by_value = {
      RawRelayCell.VALUE: RelayCell,
      RelayEarlyCell.VALUE: RelayEarlyCell,
    }
    new_cls = relay_cells_by_value[self.VALUE]

    dummy_link_protocol = None
    new_cell = new_cls._unpack(self.payload, self.circ_id, dummy_link_protocol)

    return new_cell

  def decrypt(self, digest, decryptor, interpret = False):
    """
    Decrypts a cell and checks whether it is fully decrypted,
    returning a new (Cell, fully_decrypted, digest, decryptor) tuple.
    Optionally also interprets the cell (not generally recommended).

    The method name is technically a misnomer, as it also checks whether the
    cell has been fully decrypted (after decrypting), updating the digest if so.
    However, these operations are defined per the spec as required for RELAY
    cells, and ...
      (1) it is a natural mental extension to include them here;
      (2) it would be a bit pointless to require method consumers to manually
          do all of that, for pedantry.

    :param HASH digest: running digest held with the relay
    :param cryptography.hazmat.primitives.ciphers.CipherContext decryptor:
      running stream cipher decryptor held with the relay

    :param bool interpret: (optional, defaults to **False**) Use **True** with
      caution. The spec indicates that a fully decrypted cell should be
      accounted for in digest and decryptor, independent of cell validity. Using
      **True**, while convenient, may cause an exception for a NYI relay
      command, a malformed cell, or some other reason. This option should only
      be used when the consumer will consider the circuit to have a fatal error
      in such cases, and catches/handles the exception accordingly (e.g. sending
      a DestroyCell).

    :returns: (:class:`~stem.client.cell.Cell`, bool, HASH, CipherContext) tuple
      of object copies updated as follows:
        * Cell: either :class:`~stem.client.cell.RawRelayCell` with a decrypted
          payload or :class:`~stem.client.cell.RelayCell` class or subclass, if
          **interpret** is **True** and the cell was fully decrypted
        * fully_decrypted: **bool** indicating whether the cell is fully
          decrypted
        * digest: updated via digest.update(payload), if the cell was fully
          decrypted; otherwise a copy of the original
        * decryptor: updated via decryptor.update(payload)
    """

    new_decryptor = copy.copy(decryptor)

    # actually decrypt
    decrypted_payload = new_decryptor.update(self.payload)
    new_cell = self.__class__(self.circ_id, decrypted_payload)

    # do post-decryption checks to ascertain whether cell is fully decrypted
    if new_cell.check_recognized_field():
      digest_matches, new_digest = new_cell.check_digest(digest)
      fully_decrypted = digest_matches
    else:
      new_digest = None
      fully_decrypted = False

    # only return the new_digest if the digest check meant that the cell has been fully decrypted
    #
    # furthermore, even if the digest was not updated, return a copy
    # this allows a consumer to always assume the returned digest is a different object
    digest_to_return = new_digest if fully_decrypted else digest.copy()

    if interpret and fully_decrypted:
      # this might raise an exception; oh well, we did warn about that
      new_cell = new_cell.interpret_cell()

    return new_cell, fully_decrypted, digest_to_return, new_decryptor

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'payload', cache = True)


class RawRelayCell(BaseRelayCell):
  NAME = 'RELAY'
  VALUE = 3


class RelayCell(CircuitCell):
  """
  Command concerning a relay circuit.

  :var stem.client.RelayCommand command: command to be issued
  :var int command_int: integer value of our command
  :var bytes data: payload of the cell
  :var int recognized: zero if cell is decrypted, non-zero otherwise
  :var int digest: running digest held with the relay
  :var int stream_id: specific stream this concerns
  """

  NAME = 'RELAY'
  VALUE = 3
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, command, data, digest = 0, stream_id = 0, recognized = 0, unused = b''):
    if 'HASH' in str(type(digest)):
      # Unfortunately hashlib generates from a dynamic private class so
      # isinstance() isn't such a great option. With python2/python3 the
      # name is 'hashlib.HASH' whereas PyPy calls it just 'HASH'.

      digest_packed = digest.digest()[:RELAY_DIGEST_SIZE.size]
      digest = RELAY_DIGEST_SIZE.unpack(digest_packed)
    elif stem.util._is_str(digest):
      digest_packed = digest[:RELAY_DIGEST_SIZE.size]
      digest = RELAY_DIGEST_SIZE.unpack(digest_packed)
    elif stem.util._is_int(digest):
      pass
    else:
      raise ValueError('RELAY cell digest must be a hash, string, or int but was a %s' % type(digest).__name__)

    super(RelayCell, self).__init__(circ_id, unused)
    self.command, self.command_int = RelayCommand.get(command)
    self.recognized = recognized
    self.stream_id = stream_id
    self.digest = digest
    self.data = str_tools._to_bytes(data)

    if digest == 0:
      if not stream_id and self.command in STREAM_ID_REQUIRED:
        raise ValueError('%s relay cells require a stream id' % self.command)
      elif stream_id and self.command in STREAM_ID_DISALLOWED:
        raise ValueError('%s relay cells concern the circuit itself and cannot have a stream id' % self.command)

  def pack(self, link_protocol):
    payload = bytearray()
    payload += Size.CHAR.pack(self.command_int)
    payload += Size.SHORT.pack(self.recognized)
    payload += Size.SHORT.pack(self.stream_id)
    payload += Size.LONG.pack(self.digest)
    payload += Size.SHORT.pack(len(self.data))
    payload += self.data

    return RelayCell._pack(link_protocol, bytes(payload), self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    command, content = Size.CHAR.pop(content)
    recognized, content = Size.SHORT.pop(content)  # 'recognized' field
    stream_id, content = Size.SHORT.pop(content)
    digest, content = Size.LONG.pop(content)
    data_len, content = Size.SHORT.pop(content)
    data, unused = split(content, data_len)

    if len(data) != data_len:
      raise ValueError('%s cell said it had %i bytes of data, but only had %i' % (cls.NAME, data_len, len(data)))

    return RelayCell(circ_id, command, data, digest, stream_id, recognized, unused)

  def __hash__(self):
    return stem.util._hash_attr(self, 'command_int', 'stream_id', 'digest', 'data', cache = True)


# TODO: merge the below with the RelayCell

class AlternateRelayCell(CircuitCell):
  """
  Command concerning a relay circuit.

  :var stem.client.datatype.RelayCommand command: command to be issued
  :var int command_int: integer value of our command
  :var bytes data: payload of the cell
  :var int recognized: zero if cell is decrypted, otherwise mostly non-zero
    (can rarely be zero)
  :var int digest: running digest held with the relay
  :var int stream_id: specific stream this concerns
  """

  NAME = 'RELAY'
  VALUE = 3
  IS_FIXED_SIZE = True
  CANNOT_DIRECTLY_UNPACK = True

  def __init__(self, circ_id, command, data, digest = 0, stream_id = 0, recognized = 0, unused = b''):
    digest = RelayCell._coerce_digest(digest)

    super(RelayCell, self).__init__(circ_id, unused)
    self.command, self.command_int = RelayCommand.get(command)
    self.recognized = recognized
    self.stream_id = stream_id
    self.digest = digest
    self.data = str_tools._to_bytes(data)

    if digest == 0:
      if not stream_id and self.command in STREAM_ID_REQUIRED:
        raise ValueError('%s relay cells require a stream id' % self.command)
      elif stream_id and self.command in STREAM_ID_DISALLOWED:
        raise ValueError('%s relay cells concern the circuit itself and cannot have a stream id' % self.command)

  @classmethod
  def decrypt(link_protocol, content, digest, key):
    """
    Parse the given content as an encrypted RELAY cell.
    """

    # TODO: Fill in the above pydocs, deduplicate with the other decrypt
    # method, yadda yadda. Starting with a minimal stub to see if this makes
    # the Circuit class better. I'll circle back to clean up this module if it
    # works.

    if len(content) != link_protocol.fixed_cell_length:
      raise stem.ProtocolError('RELAY cells should be %i bytes, but received %i' % (link_protocol.fixed_cell_length, len(content)))

    circ_id, content = link_protocol.circ_id_size.pop(content)
    command, payload = Size.CHAR.pop(content)

    if command != RelayCell.VALUE:
      raise stem.ProtocolError('Cannot decrypt as a RELAY cell. This had command %i instead.' % command)

    key = copy.copy(key)
    decrypted = key.update(payload)

    # TODO: Integrate with check_digest() and flag for integrating if we're
    # fully decrypted. For the moment we only handle direct responses (ie. all
    # the cells we receive can be fully decrypted) but if we attempt to support
    # relaying we'll need to pass along cells we can only partially decrypt.

    return RelayCell._unpack(decrypted, circ_id, link_protocol), key, digest

  @staticmethod
  def _coerce_digest(digest):
    """
    Coerce any of HASH, str, int into the proper digest type for packing

    :param HASH,str,int digest: digest to be coerced
    :returns: digest in type appropriate for packing

    :raises: **ValueError** if input digest type is unsupported
    """

    if 'HASH' in str(type(digest)):
      # Unfortunately hashlib generates from a dynamic private class so
      # isinstance() isn't such a great option. With python2/python3 the
      # name is 'hashlib.HASH' whereas PyPy calls it just 'HASH'.

      digest_packed = digest.digest()[:RELAY_DIGEST_SIZE.size]
      digest = RELAY_DIGEST_SIZE.unpack(digest_packed)
    elif stem.util._is_str(digest):
      digest_packed = digest[:RELAY_DIGEST_SIZE.size]
      digest = RELAY_DIGEST_SIZE.unpack(digest_packed)
    elif stem.util._is_int(digest):
      pass
    else:
      raise ValueError('RELAY cell digest must be a hash, string, or int but was a %s' % type(digest).__name__)

    return digest

  def pack(self, link_protocol):
    payload = self.pack_payload()

    return RelayCell._pack(link_protocol, payload, unused = b'', circ_id = self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    command, recognized, stream_id, digest, data_len, data, unused = RelayCell._unpack_payload(content)

    if len(data) != data_len:
      raise ValueError('%s cell said it had %i bytes of data, but only had %i' % (cls.NAME, data_len, len(data)))

    return RelayCell(circ_id, command, data, digest, stream_id, recognized, unused)

  @staticmethod
  def _unpack_payload(content):
    """
    Directly interpret the payload without any validation.

    :param bytes content: cell payload

    :returns: (command, recognized, stream_id, digest, data_len, data, unused) tuple
    """

    command, content = Size.CHAR.pop(content)
    recognized, content = Size.SHORT.pop(content)  # 'recognized' field
    stream_id, content = Size.SHORT.pop(content)
    digest, content = Size.LONG.pop(content)
    data_len, content = Size.SHORT.pop(content)
    data, unused = split(content, data_len)

    return command, recognized, stream_id, digest, data_len, data, unused

  def apply_digest(self, digest, prep_cell = True):
    """
    Calculates, updates, and applies the digest to the cell payload,
    returning a new (cell, digest) tuple.

    :param HASH digest: running digest held with the relay
    :param bool prep_cell: preps the cell payload according to the spec, if
      **True** (default)
      if **False**, the digest will be calculated as-is, namely:
        * the 'recognized' field will not be set to 0,
        * the digest field will not be set to 0,
        * and any 'unused' padding will be taken as-is.
      Use **False** with caution.

    :returns: (:class:`~stem.client.cell.RelayCell`, HASH) tuple of object
      copies updated as follows:
        * digest: updated via digest.update(payload)
        * RelayCell: a copy of self, with the following updates:
          * RelayCell.recognized: set to 0, if prep_cell is **True**
          * RelayCell.digest: updated with the calculated digest
          * RelayCell.unused: treated as padding and overwritten, if prep_cell
            is **True**
    """

    if prep_cell:
      new_cell_recognized = 0
      new_cell_digest = 0
      new_cell_unused = b''
    else:
      new_cell_recognized = self.recognized
      new_cell_digest = self.digest
      new_cell_unused = self.unused

    new_digest = digest.copy()
    new_cell = RelayCell(self.circ_id, self.command, self.data, digest = new_cell_digest, stream_id = self.stream_id, recognized = new_cell_recognized, unused = new_cell_unused)

    payload_without_updated_digest = new_cell.pack_payload()
    new_digest.update(payload_without_updated_digest)
    new_cell.digest = RelayCell._coerce_digest(new_digest)

    return new_cell, new_digest

  def encrypt(self, link_protocol, digest, encryptor, **kwargs):
    """
    Preps a cell payload, including calculating digest, and encrypts it,
    returning a new (RawRelayCell, digest, encryptor) tuple.

    The method name is technically a misnomer, as it also preps cell payload
    and applies the digest, prior to encrypting. However, these operations
    are defined per the spec as required for RELAY cells, and ...
      (1) it is a natural mental extension to include them here;
      (2) it would be a bit pointless to require method consumers to manually
          call both, for pedantry.

    :param int link_protocol: link protocol version
    :param HASH digest: running digest held with the relay
    :param cryptography.hazmat.primitives.ciphers.CipherContext encryptor:
      running stream cipher encryptor held with the relay

    :param bool prep_cell: (optional, defaults to **True**) refer to
      :func:`~stem.client.cell.RelayCell.apply_digest`

    :returns: (bytes, HASH, CipherContext)
      tuple of object copies updated as follows:
        * bytes: encrypted cell payload
        * digest: updated via digest.update(payload)
        * encryptor: updated via encryptor.update(payload_with_digest)
    """

    unencrypted_cell, new_digest = self.apply_digest(digest, **kwargs)
    new_encryptor = copy.copy(encryptor)
    encrypted_payload = new_encryptor.update(unencrypted_cell.pack_payload())
    encrypted_cell = RawRelayCell(unencrypted_cell.circ_id, encrypted_payload)

    return encrypted_cell.pack(link_protocol), new_digest, new_encryptor

  def pack_payload(self, **kwargs):
    """
    Convenience method for running
    :func:`~stem.client.cell.RelayCell._pack_payload` on self.

    :param bool pad_remaining: (optional, defaults to **True**) pads up to
      payload size if **True**

    :returns: **bytes** with the packed payload
    """

    return RelayCell._pack_payload(self.command_int, self.recognized, self.stream_id, self.digest, len(self.data), self.data, self.unused, **kwargs)

  @staticmethod
  def _pack_payload(command_int, recognized, stream_id, digest, data_len, data, unused = b'', pad_remainder = True):
    """
    Directly pack the payload without any validation beyond Size constraints.

    :param int command_int: integer value of our command
    :param int recognized: zero if cell is decrypted, otherwise mostly non-zero
      (can rarely be zero)
    :param int stream_id: specific stream this concerns
    :param HASH,str,int digest: running digest held with the relay
    :param int data_len: length of body data
    :param bytes data: body data of the cell
    :param bytes unused: padding bytes to include after data
    :param bool pad_remaining: pads up to payload size if **True**

    :returns: **bytes** with the packed payload
    """

    payload = bytearray()
    payload += Size.CHAR.pack(command_int)
    payload += Size.SHORT.pack(recognized)
    payload += Size.SHORT.pack(stream_id)
    payload += Size.LONG.pack(RelayCell._coerce_digest(digest))
    payload += Size.SHORT.pack(data_len)
    payload += data
    payload += unused

    if len(payload) > FIXED_PAYLOAD_LEN:
      raise ValueError('Payload is too large (%i bytes), must not be more than %i.' % (len(payload), FIXED_PAYLOAD_LEN))

    if pad_remainder:
      # right now, it is acceptable to pad the remaining portion with ZEROs instead of random
      # this is done due to threat model and simplifying some implementation
      # however: in the future (TODO), this may become against the spec; see prop 289
      payload += ZERO * (FIXED_PAYLOAD_LEN - len(payload))

    return bytes(payload)

  def __hash__(self):
    return stem.util._hash_attr(self, 'command_int', 'stream_id', 'digest', 'data', cache = True)


class DestroyCell(CircuitCell):
  """
  Closes the given circuit.

  :var stem.client.CloseReason reason: reason the circuit is being closed
  :var int reason_int: integer value of our closure reason
  """

  NAME = 'DESTROY'
  VALUE = 4
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, reason = CloseReason.NONE, unused = b''):
    super(DestroyCell, self).__init__(circ_id, unused)
    self.reason, self.reason_int = CloseReason.get(reason)

  def pack(self, link_protocol):
    return DestroyCell._pack(link_protocol, Size.CHAR.pack(self.reason_int), self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    reason, unused = Size.CHAR.pop(content)
    return DestroyCell(circ_id, reason, unused)

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'reason_int', cache = True)


class CreateFastCell(CircuitCell):
  """
  Create a circuit with our first hop. This is lighter weight than further hops
  because we've already established the relay's identity and secret key.

  :var bytes key_material: randomized key material
  """

  NAME = 'CREATE_FAST'
  VALUE = 5
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, key_material = None, unused = b''):
    if not key_material:
      key_material = os.urandom(HASH_LEN)
    elif len(key_material) != HASH_LEN:
      raise ValueError('Key material should be %i bytes, but was %i' % (HASH_LEN, len(key_material)))

    super(CreateFastCell, self).__init__(circ_id, unused)
    self.key_material = key_material

  def pack(self, link_protocol):
    return CreateFastCell._pack(link_protocol, self.key_material, self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    key_material, unused = split(content, HASH_LEN)

    if len(key_material) != HASH_LEN:
      raise ValueError('Key material should be %i bytes, but was %i' % (HASH_LEN, len(key_material)))

    return CreateFastCell(circ_id, key_material, unused)

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'key_material', cache = True)


class CreatedFastCell(CircuitCell):
  """
  CREATE_FAST reply.

  :var bytes key_material: randomized key material
  :var bytes derivative_key: hash proving the relay knows our shared key
  """

  NAME = 'CREATED_FAST'
  VALUE = 6
  IS_FIXED_SIZE = True

  def __init__(self, circ_id, derivative_key, key_material = None, unused = b''):
    if not key_material:
      key_material = os.urandom(HASH_LEN)
    elif len(key_material) != HASH_LEN:
      raise ValueError('Key material should be %i bytes, but was %i' % (HASH_LEN, len(key_material)))

    if len(derivative_key) != HASH_LEN:
      raise ValueError('Derivatived key should be %i bytes, but was %i' % (HASH_LEN, len(derivative_key)))

    super(CreatedFastCell, self).__init__(circ_id, unused)
    self.key_material = key_material
    self.derivative_key = derivative_key

  def pack(self, link_protocol):
    return CreatedFastCell._pack(link_protocol, self.key_material + self.derivative_key, self.unused, self.circ_id)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    if len(content) < HASH_LEN * 2:
      raise ValueError('Key material and derivatived key should be %i bytes, but was %i' % (HASH_LEN * 2, len(content)))

    key_material, content = split(content, HASH_LEN)
    derivative_key, content = split(content, HASH_LEN)

    return CreatedFastCell(circ_id, derivative_key, key_material, content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'circ_id', 'derivative_key', 'key_material', cache = True)


class VersionsCell(Cell):
  """
  Link version negotiation cell.

  :var list versions: link versions
  """

  NAME = 'VERSIONS'
  VALUE = 7
  IS_FIXED_SIZE = False

  def __init__(self, versions):
    super(VersionsCell, self).__init__()
    self.versions = versions

  def pack(self, link_protocol):
    payload = b''.join([Size.SHORT.pack(v) for v in self.versions])
    return VersionsCell._pack(link_protocol, payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    link_protocols = []

    while content:
      version, content = Size.SHORT.pop(content)
      link_protocols.append(version)

    return VersionsCell(link_protocols)

  def __hash__(self):
    return stem.util._hash_attr(self, 'versions', cache = True)


class NetinfoCell(Cell):
  """
  Information relays exchange about each other.

  :var datetime timestamp: current time
  :var stem.client.Address receiver_address: receiver's OR address
  :var list sender_addresses: sender's OR addresses
  """

  NAME = 'NETINFO'
  VALUE = 8
  IS_FIXED_SIZE = True

  def __init__(self, receiver_address, sender_addresses, timestamp = None, unused = b''):
    super(NetinfoCell, self).__init__(unused)
    self.timestamp = timestamp if timestamp else datetime.datetime.now()
    self.receiver_address = receiver_address
    self.sender_addresses = sender_addresses

  def pack(self, link_protocol):
    payload = bytearray()
    payload += Size.LONG.pack(int(datetime_to_unix(self.timestamp)))
    payload += self.receiver_address.pack()
    payload += Size.CHAR.pack(len(self.sender_addresses))

    for addr in self.sender_addresses:
      payload += addr.pack()

    return NetinfoCell._pack(link_protocol, bytes(payload), self.unused)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    timestamp, content = Size.LONG.pop(content)
    receiver_address, content = Address.pop(content)

    sender_addresses = []
    sender_addr_count, content = Size.CHAR.pop(content)

    for i in range(sender_addr_count):
      addr, content = Address.pop(content)
      sender_addresses.append(addr)

    return NetinfoCell(receiver_address, sender_addresses, datetime.datetime.utcfromtimestamp(timestamp), unused = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'timestamp', 'receiver_address', 'sender_addresses', cache = True)


class RelayEarlyCell(CircuitCell):
  NAME = 'RELAY_EARLY'
  VALUE = 9
  IS_FIXED_SIZE = True

  def __init__(self):
    super(RelayEarlyCell, self).__init__()  # TODO: implement


class Create2Cell(CircuitCell):
  NAME = 'CREATE2'
  VALUE = 10
  IS_FIXED_SIZE = True

  def __init__(self):
    super(Create2Cell, self).__init__()  # TODO: implement


class Created2Cell(Cell):
  NAME = 'CREATED2'
  VALUE = 11
  IS_FIXED_SIZE = True

  def __init__(self):
    super(Created2Cell, self).__init__()  # TODO: implement


class PaddingNegotiateCell(Cell):
  NAME = 'PADDING_NEGOTIATE'
  VALUE = 12
  IS_FIXED_SIZE = True

  def __init__(self):
    super(PaddingNegotiateCell, self).__init__()  # TODO: implement


class VPaddingCell(Cell):
  """
  Variable length randomized content to either keep activity going on a circuit.

  :var bytes payload: randomized payload
  """

  NAME = 'VPADDING'
  VALUE = 128
  IS_FIXED_SIZE = False

  def __init__(self, size = None, payload = None):
    if size is None and payload is None:
      raise ValueError('VPaddingCell constructor must specify payload or size')
    elif size is not None and size < 0:
      raise ValueError('VPaddingCell size (%s) cannot be negative' % size)
    elif size is not None and payload is not None and size != len(payload):
      raise ValueError('VPaddingCell constructor specified both a size of %i bytes and payload of %i bytes' % (size, len(payload)))

    super(VPaddingCell, self).__init__()
    self.payload = payload if payload is not None else os.urandom(size)

  def pack(self, link_protocol):
    return VPaddingCell._pack(link_protocol, self.payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    return VPaddingCell(payload = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'payload', cache = True)


class CertsCell(Cell):
  """
  Certificate held by the relay we're communicating with.

  :var list certificates: :class:`~stem.client.Certificate` of the relay
  """

  NAME = 'CERTS'
  VALUE = 129
  IS_FIXED_SIZE = False

  def __init__(self, certs, unused = b''):
    super(CertsCell, self).__init__(unused)
    self.certificates = certs

  def pack(self, link_protocol):
    return CertsCell._pack(link_protocol, Size.CHAR.pack(len(self.certificates)) + b''.join([cert.pack() for cert in self.certificates]), self.unused)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    cert_count, content = Size.CHAR.pop(content)
    certs = []

    for i in range(cert_count):
      if not content:
        raise ValueError('CERTS cell indicates it should have %i certificates, but only contained %i' % (cert_count, len(certs)))

      cert, content = Certificate.pop(content)
      certs.append(cert)

    return CertsCell(certs, unused = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'certificates', cache = True)


class AuthChallengeCell(Cell):
  """
  First step of the authentication handshake.

  :var bytes challenge: random bytes for us to sign to authenticate
  :var list methods: authentication methods supported by the relay we're
    communicating with
  """

  NAME = 'AUTH_CHALLENGE'
  VALUE = 130
  IS_FIXED_SIZE = False

  def __init__(self, methods, challenge = None, unused = b''):
    if not challenge:
      challenge = os.urandom(AUTH_CHALLENGE_SIZE)
    elif len(challenge) != AUTH_CHALLENGE_SIZE:
      raise ValueError('AUTH_CHALLENGE must be %i bytes, but was %i' % (AUTH_CHALLENGE_SIZE, len(challenge)))

    super(AuthChallengeCell, self).__init__(unused)
    self.challenge = challenge
    self.methods = methods

  def pack(self, link_protocol):
    payload = bytearray()
    payload += self.challenge
    payload += Size.SHORT.pack(len(self.methods))

    for method in self.methods:
      payload += Size.SHORT.pack(method)

    return AuthChallengeCell._pack(link_protocol, bytes(payload), self.unused)

  @classmethod
  def _unpack(cls, content, circ_id, link_protocol):
    min_size = AUTH_CHALLENGE_SIZE + Size.SHORT.size
    if len(content) < min_size:
      raise ValueError('AUTH_CHALLENGE payload should be at least %i bytes, but was %i' % (min_size, len(content)))

    challenge, content = split(content, AUTH_CHALLENGE_SIZE)
    method_count, content = Size.SHORT.pop(content)

    if len(content) < method_count * Size.SHORT.size:
      raise ValueError('AUTH_CHALLENGE should have %i methods, but only had %i bytes for it' % (method_count, len(content)))

    methods = []

    for i in range(method_count):
      method, content = Size.SHORT.pop(content)
      methods.append(method)

    return AuthChallengeCell(methods, challenge, unused = content)

  def __hash__(self):
    return stem.util._hash_attr(self, 'challenge', 'methods', cache = True)


class AuthenticateCell(Cell):
  NAME = 'AUTHENTICATE'
  VALUE = 131
  IS_FIXED_SIZE = False

  def __init__(self):
    super(AuthenticateCell, self).__init__()  # TODO: implement


class AuthorizeCell(Cell):
  NAME = 'AUTHORIZE'
  VALUE = 132
  IS_FIXED_SIZE = False

  def __init__(self):
    super(AuthorizeCell, self).__init__()  # TODO: implement
