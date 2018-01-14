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
    |  |- RelayCell - End-to-end data.                (section 5.5 and 6)
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
    |- pack - Provides encoded bytes for this cell class.
    +- unpack - Decodes bytes for this cell class.
"""

import inspect
import io
import sys

from stem import UNDEFINED
from stem.client import ZERO, Certificate, Size

FIXED_PAYLOAD_LEN = 509


class Cell(object):
  """
  Metadata for ORPort cells.

  :var str name: command of the cell
  :var int value: integer value of the command on the wire
  :var bool fixed_size: **True** if cells have a fixed length,
    **False** if variable
  :var bool for_circuit: **True** if command is for a circuit,
    **False** otherwise
  """

  NAME = 'UNKNOWN'
  VALUE = -1
  IS_FIXED_SIZE = False

  @staticmethod
  def by_name(name):
    """
    Provides cell attributes by its name.

    :parm str name: cell command to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for _, cls in inspect.getmembers(sys.modules[__name__]):
      if name == getattr(cls, 'NAME', UNDEFINED):
        return cls

    raise ValueError("'%s' isn't a valid cell type" % name)

  @staticmethod
  def by_value(value):
    """
    Provides cell attributes by its value.

    :parm int value: cell value to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for _, cls in inspect.getmembers(sys.modules[__name__]):
      if value == getattr(cls, 'VALUE', UNDEFINED):
        return cls

    raise ValueError("'%s' isn't a valid cell value" % value)

  @staticmethod
  def unpack(content, link_version):
    """
    Unpacks encoded bytes into a series of cells.

    :param bytes content: payload to decode
    :param int link_version: link protocol version

    :returns: **list** of :class:`~stem.client.cell.Cell` subclasses

    :raises:
      * ValueError if content is malformed
      * NotImplementedError if unable to unpack this cell type
    """

    cells = []

    while content:
      circ_id, content = Size.SHORT.pop(content) if link_version < 4 else Size.LONG.pop(content)
      command, content = Size.CHAR.pop(content)
      cls = Cell.by_value(command)

      if cls.IS_FIXED_SIZE:
        payload_len = FIXED_PAYLOAD_LEN
      else:
        payload_len, content = Size.SHORT.pop(content)

      if len(content) < payload_len:
        raise ValueError('%s cell should have a payload of %i bytes, but only had %i' % (cls.NAME, payload_len, len(content)))

      payload = content[:payload_len]
      content = content[payload_len:]

      cells.append(cls._unpack(payload, link_version, circ_id))

    return cells

  @classmethod
  def _pack(cls, link_version, payload, circ_id = 0):
    """
    Provides bytes that can be used on the wire for these cell attributes.
    Format of a properly packed cell depends on if it's fixed or variable
    sized...

    ::

      Fixed:    [ CircuitID ][ Command ][ Payload ][ Padding ]
      Variable: [ CircuitID ][ Command ][ Size ][ Payload ]

    :param str name: cell command
    :param int link_version: link protocol version
    :param bytes payload: cell payload
    :param int circ_id: circuit id, if a CircuitCell

    :return: **bytes** with the encoded payload

    :raise: **ValueError** if cell type invalid or payload is too large
    """

    cell = io.BytesIO()
    cell.write(Size.LONG.pack(circ_id) if link_version > 3 else Size.SHORT.pack(circ_id))
    cell.write(Size.CHAR.pack(cls.VALUE))
    cell.write(b'' if cls.IS_FIXED_SIZE else Size.SHORT.pack(len(payload)))
    cell.write(payload)

    # pad fixed sized cells to the required length

    if cls.IS_FIXED_SIZE:
      cell_size = cell.seek(0, io.SEEK_END)
      fixed_cell_len = 514 if link_version > 3 else 512

      if cell_size > fixed_cell_len:
        raise ValueError('Payload of %s is too large (%i bytes), must be less than %i' % (cls.NAME, cell_size, fixed_cell_len))

      cell.write(ZERO * (fixed_cell_len - cell_size))

    return cell.getvalue()

  @classmethod
  def _unpack(cls, content, circ_id, link_version):
    """
    Subclass implementation for unpacking cell content.

    :param bytes content: payload to decode
    :param int link_version: link protocol version
    :param int circ_id: circuit id cell is for

    :returns: instance of this cell type

    :raises: **ValueError** if content is malformed
    """

    raise NotImplementedError('Unpacking not yet implemented for %s cells' % cls.NAME)


class CircuitCell(Cell):
  """
  Cell concerning circuits.
  """

  @classmethod
  def _pack(cls, link_version, payload, circ_id):
    """
    Provides bytes that can be used on the wire for these cell attributes.

    :param str name: cell command
    :param int link_version: link protocol version
    :param bytes payload: cell payload
    :param int circ_id: circuit id

    :raise: **ValueError** if cell type invalid or payload is too large
    """

    if circ_id is None and cls.NAME.startswith('CREATE'):
      # Since we're initiating the circuit we pick any value from a range
      # that's determined by our link version.

      circ_id = 0x80000000 if link_version > 3 else 0x01
    else:
      raise ValueError('%s cells require a circ_id' % cls.NAME)

    return Cell._pack(link_version, payload, circ_id)


class PaddingCell(Cell):
  NAME = 'PADDING'
  VALUE = 0
  IS_FIXED_SIZE = True


class CreateCell(CircuitCell):
  NAME = 'CREATE'
  VALUE = 1
  IS_FIXED_SIZE = True


class CreatedCell(CircuitCell):
  NAME = 'CREATED'
  VALUE = 2
  IS_FIXED_SIZE = True


class RelayCell(CircuitCell):
  NAME = 'RELAY'
  VALUE = 3
  IS_FIXED_SIZE = True


class DestroyCell(CircuitCell):
  NAME = 'DESTROY'
  VALUE = 4
  IS_FIXED_SIZE = True


class CreateFastCell(CircuitCell):
  NAME = 'CREATE_FAST'
  VALUE = 5
  IS_FIXED_SIZE = True


class CreatedFastCell(CircuitCell):
  NAME = 'CREATED_FAST'
  VALUE = 6
  IS_FIXED_SIZE = True


class VersionsCell(Cell):
  """
  Link version negotiation cell.

  :var list versions: link versions
  """

  NAME = 'VERSIONS'
  VALUE = 7
  IS_FIXED_SIZE = False

  def __init__(self, versions):
    self.versions = versions

  @classmethod
  def pack(cls, versions):
    """
    Provides the payload for a series of link versions.

    :param list versions: link versions to serialize

    :returns: **bytes** with a payload for these versions
    """

    # Used for link version negotiation so we don't have that yet. This is fine
    # since VERSION cells avoid most version dependent attributes.

    payload = b''.join([Size.SHORT.pack(v) for v in versions])
    return cls._pack(2, payload)

  @classmethod
  def _unpack(cls, content, circ_id, link_version):
    link_versions = []

    while content:
      version, content = Size.SHORT.pop(content)
      link_versions.append(version)

    return VersionsCell(link_versions)


class NetinfoCell(Cell):
  NAME = 'NETINFO'
  VALUE = 8
  IS_FIXED_SIZE = True


class RelayEarlyCell(CircuitCell):
  NAME = 'RELAY_EARLY'
  VALUE = 9
  IS_FIXED_SIZE = True


class Create2Cell(CircuitCell):
  NAME = 'CREATE2'
  VALUE = 10
  IS_FIXED_SIZE = True


class Created2Cell(Cell):
  NAME = 'CREATED2'
  VALUE = 11
  IS_FIXED_SIZE = True


class PaddingNegotiateCell(Cell):
  NAME = 'PADDING_NEGOTIATE'
  VALUE = 12
  IS_FIXED_SIZE = True


class VPaddingCell(Cell):
  NAME = 'VPADDING'
  VALUE = 128
  IS_FIXED_SIZE = False


class CertsCell(Cell):
  """
  Certificate held by the relay we're communicating with.

  :var list certificates: :class:`~stem.client.Certificate` of the relay
  """

  NAME = 'CERTS'
  VALUE = 129
  IS_FIXED_SIZE = False

  def __init__(self, certs):
    self.certificates = certs

  @classmethod
  def pack(cls, certs, link_version):
    """
    Provides the payload for a series of certificates.

    :param list certs: series of :class:`~stem.client.Certificate` for the cell
    :param int link_version: link protocol version

    :returns: **bytes** with a payload for these versions
    """

    payload = io.BytesIO()
    payload.write(Size.CHAR.pack(len(certs)))

    for cert in certs:
      payload.write(Size.CHAR.pack(cert.type))
      payload.write(Size.SHORT.pack(len(cert.value)))
      payload.write(cert.value)

    return cls._pack(link_version, payload.getvalue())

  @classmethod
  def _unpack(cls, content, circ_id, link_version):
    cert_count, content = Size.CHAR.pop(content)
    certs = []

    for i in range(cert_count):
      if not content:
        raise ValueError('CERTS cell indicates it should have %i certificates, but only contained %i' % (cert_count, len(certs)))

      cert_type, content = Size.CHAR.pop(content)
      cert_size, content = Size.SHORT.pop(content)

      if cert_size > len(content):
        raise ValueError('CERTS cell should have a certificate with %i bytes, but only had %i remaining' % (cert_size, len(content)))

      cert_bytes = content[:cert_size]
      content = content[cert_size:]
      certs.append(Certificate(cert_type, cert_bytes))

    return CertsCell(certs)


class AuthChallengeCell(Cell):
  NAME = 'AUTH_CHALLENGE'
  VALUE = 130
  IS_FIXED_SIZE = False


class AuthenticateCell(Cell):
  NAME = 'AUTHENTICATE'
  VALUE = 131
  IS_FIXED_SIZE = False


class AuthorizeCell(Cell):
  NAME = 'AUTHORIZE'
  VALUE = 132
  IS_FIXED_SIZE = False
