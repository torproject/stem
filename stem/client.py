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

import collections
import struct

from stem.util import enum

ZERO = '\x00'


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

  @staticmethod
  def by_name(name):
    """
    Provides cell attributes by its name.

    :parm str name: cell command to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for cell_type in CELL_TYPES:
      if name == cell_type.name:
        return cell_type

    raise ValueError("'%s' isn't a valid cell type" % name)

  @staticmethod
  def by_value(value):
    """
    Provides cell attributes by its value.

    :parm int value: cell value to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for cell_type in CELL_TYPES:
      if value == cell_type.value:
        return cell_type

    raise ValueError("'%s' isn't a valid cell value" % value)

  @staticmethod
  def pack(name, link_version, payload, circ_id = None):
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

    attr = Cell.by_name(name)
    circ_id_len = Pack.LONG if link_version > 3 else Pack.SHORT

    if attr.for_circuit and circ_id is None:
      if name.startswith('CREATE'):
        # Since we're initiating the circuit we pick any value from a range
        # that's determined by our link version.

        circ_id = 0x80000000 if link_version > 3 else 0x01
      else:
        raise ValueError('%s cells require a circ_id' % name)
    elif not attr.for_circuit:
      if circ_id:
        raise ValueError("%s cells don't concern circuits, circ_id is unused" % name)

      circ_id = 0  # field is still mandatory for all cells

    packed_circ_id = struct.pack(circ_id_len, circ_id)
    packed_command = struct.pack(Pack.CHAR, attr.value)
    packed_size = b'' if attr.fixed_size else struct.pack(Pack.SHORT, len(payload))
    cell = b''.join((packed_circ_id, packed_command, packed_size, payload))

    # pad fixed sized cells to the required length

    if attr.fixed_size:
      fixed_cell_len = 514 if link_version > 3 else 512

      if len(cell) > fixed_cell_len:
        raise ValueError('Payload of %s is too large (%i bytes), must be less than %i' % (name, len(cell), fixed_cell_len))

      cell += ZERO * (fixed_cell_len - len(cell))

    return cell


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

  return b''.join([struct.pack(Pack.SHORT, v) for v in versions])


Pack = enum.Enum(
  ('CHAR', '!B'),       # 1 byte
  ('SHORT', '!H'),      # 2 bytes
  ('LONG', '!L'),       # 4 bytes
  ('LONG_LONG', '!Q'),  # 8 bytes
)

CELL_TYPES = (
  Cell('PADDING', 0, True, False),              # Padding                  (section 7.2)
  Cell('CREATE', 1, True, True),                # Create a circuit         (section 5.1)
  Cell('CREATED', 2, True, True),               # Acknowledge create       (section 5.1)
  Cell('RELAY', 3, True, True),                 # End-to-end data          (section 5.5 and 6)
  Cell('DESTROY', 4, True, True),               # Stop using a circuit     (section 5.4)
  Cell('CREATE_FAST', 5, True, True),           # Create a circuit, no PK  (section 5.1)
  Cell('CREATED_FAST', 6, True, True),          # Circuit created, no PK   (section 5.1)
  Cell('VERSIONS', 7, False, False),            # Negotiate proto version  (section 4)
  Cell('NETINFO', 8, True, False),              # Time and address info    (section 4.5)
  Cell('RELAY_EARLY', 9, True, True),           # End-to-end data; limited (section 5.6)
  Cell('CREATE2', 10, True, True),              # Extended CREATE cell     (section 5.1)
  Cell('CREATED2', 11, True, True),             # Extended CREATED cell    (section 5.1)
  Cell('PADDING_NEGOTIATE', 12, True, False),   # Padding negotiation      (section 7.2)
  Cell('VPADDING', 128, False, False),          # Variable-length padding  (section 7.2)
  Cell('CERTS', 129, False, False),             # Certificates             (section 4.2)
  Cell('AUTH_CHALLENGE', 130, False, False),    # Challenge value          (section 4.3)
  Cell('AUTHENTICATE', 131, False, False),      # Client authentication    (section 4.5)
  Cell('AUTHORIZE', 132, False, False),         # Client authorization     (not yet used)
)
