# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Messages communicated over a Tor relay's ORPort.

.. versionadded:: 1.7.0
"""

import collections
import struct

from stem.client import ZERO, Pack


class Cell(collections.namedtuple('Cell', ['name', 'value', 'fixed_size', 'for_circuit'])):
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
  IS_FOR_CIRCUIT = False

  @staticmethod
  def by_name(name):
    """
    Provides cell attributes by its name.

    :parm str name: cell command to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for cls in CELL_TYPES:
      if name == cls.NAME:
        return cls

    raise ValueError("'%s' isn't a valid cell type" % name)

  @staticmethod
  def by_value(value):
    """
    Provides cell attributes by its value.

    :parm int value: cell value to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for cls in CELL_TYPES:
      if value == cls.VALUE:
        return cls

    raise ValueError("'%s' isn't a valid cell value" % value)

  @classmethod
  def _pack(cls, link_version, payload, circ_id = None):
    """
    Provides bytes that can be used on the wire for these cell attributes.

    :param str name: cell command
    :param int link_version: link protocol version
    :param bytes payload: cell payload
    :param int circ_id: circuit id, if for a circuit

    :raise: **ValueError** if...
      * cell type or circuit id is invalid
      * payload is too large
    """

    circ_id_len = Pack.LONG if link_version > 3 else Pack.SHORT

    if cls.IS_FOR_CIRCUIT and circ_id is None:
      if cls.NAME.startswith('CREATE'):
        # Since we're initiating the circuit we pick any value from a range
        # that's determined by our link version.

        circ_id = 0x80000000 if link_version > 3 else 0x01
      else:
        raise ValueError('%s cells require a circ_id' % cls.NAME)
    elif not cls.IS_FOR_CIRCUIT:
      if circ_id:
        raise ValueError("%s cells don't concern circuits, circ_id is unused" % cls.NAME)

      circ_id = 0  # field is still mandatory for all cells

    packed_circ_id = struct.pack(circ_id_len, circ_id)
    packed_command = struct.pack(Pack.CHAR, cls.VALUE)
    packed_size = b'' if cls.IS_FIXED_SIZE else struct.pack(Pack.SHORT, len(payload))
    cell = b''.join((packed_circ_id, packed_command, packed_size, payload))

    # pad fixed sized cells to the required length

    if cls.IS_FIXED_SIZE:
      fixed_cell_len = 514 if link_version > 3 else 512

      if len(cell) > fixed_cell_len:
        raise ValueError('Payload of %s is too large (%i bytes), must be less than %i' % (cls.NAME, len(cell), fixed_cell_len))

      cell += ZERO * (fixed_cell_len - len(cell))

    return cell


class PaddingCell(Cell):
  NAME = 'PADDING'
  VALUE = 0
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = False


class CreateCell(Cell):
  NAME = 'CREATE'
  VALUE = 1
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class CreatedCell(Cell):
  NAME = 'CREATED'
  VALUE = 2
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class RelayCell(Cell):
  NAME = 'RELAY'
  VALUE = 3
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class DestroyCell(Cell):
  NAME = 'DESTROY'
  VALUE = 4
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class CreateFastCell(Cell):
  NAME = 'CREATE_FAST'
  VALUE = 5
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class CreatedFastCell(Cell):
  NAME = 'CREATED_FAST'
  VALUE = 6
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class VersionsCell(Cell):
  """
  Link version negotiation cell.
  """

  NAME = 'VERSIONS'
  VALUE = 7
  IS_FIXED_SIZE = False
  IS_FOR_CIRCUIT = False

  @classmethod
  def pack(cls, versions):
    """
    Provides the payload for a series of link versions.

    :param list versions: link versions to serialize

    :returns: **bytes** with a payload for these versions
    """

    # Used for link version negotiation so we don't have that yet. This is fine
    # since VERSION cells avoid most version dependent attributes.

    payload = b''.join([struct.pack(Pack.SHORT, v) for v in versions])
    return cls._pack(3, payload)


class NetinfoCell(Cell):
  NAME = 'NETINFO'
  VALUE = 8
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = False


class RelayEarlyCell(Cell):
  NAME = 'RELAY_EARLY'
  VALUE = 9
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class Create2Cell(Cell):
  NAME = 'CREATE2'
  VALUE = 10
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = True


class Created2Cell(Cell):
  NAME = 'CREATED2'
  VALUE = 11
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = False


class PaddingNegotiateCell(Cell):
  NAME = 'PADDING_NEGOTIATE'
  VALUE = 12
  IS_FIXED_SIZE = True
  IS_FOR_CIRCUIT = False


class VPaddingCell(Cell):
  NAME = 'VPADDING'
  VALUE = 128
  IS_FIXED_SIZE = False
  IS_FOR_CIRCUIT = False


class CertsCell(Cell):
  NAME = 'CERTS'
  VALUE = 129
  IS_FIXED_SIZE = False
  IS_FOR_CIRCUIT = False


class AuthChallengeCell(Cell):
  NAME = 'AUTH_CHALLENGE'
  VALUE = 130
  IS_FIXED_SIZE = False
  IS_FOR_CIRCUIT = False


class AuthenticateCell(Cell):
  NAME = 'AUTHENTICATE'
  VALUE = 131
  IS_FIXED_SIZE = False
  IS_FOR_CIRCUIT = False


class AuthorizeCell(Cell):
  NAME = 'AUTHORIZE'
  VALUE = 132
  IS_FIXED_SIZE = False
  IS_FOR_CIRCUIT = False


CELL_TYPES = (
  PaddingCell,            # Padding                  (section 7.2)
  CreateCell,             # Create a circuit         (section 5.1)
  CreatedCell,            # Acknowledge create       (section 5.1)
  RelayCell,              # End-to-end data          (section 5.5 and 6)
  DestroyCell,            # Stop using a circuit     (section 5.4)
  CreateFastCell,         # Create a circuit, no PK  (section 5.1)
  CreatedFastCell,        # Circuit created, no PK   (section 5.1)
  VersionsCell,           # Negotiate proto version  (section 4)
  NetinfoCell,            # Time and address info    (section 4.5)
  RelayEarlyCell,         # End-to-end data; limited (section 5.6)
  Create2Cell,            # Extended CREATE cell     (section 5.1)
  Created2Cell,           # Extended CREATED cell    (section 5.1)
  PaddingNegotiateCell,   # Padding negotiation      (section 7.2)
  VPaddingCell,           # Variable-length padding  (section 7.2)
  CertsCell,              # Certificates             (section 4.2)
  AuthChallengeCell,      # Challenge value          (section 4.3)
  AuthenticateCell,       # Client authentication    (section 4.5)
  AuthorizeCell,          # Client authorization     (not yet used)
)
