# Copyright 2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for interacting with the ORPort provided by Tor relays. The
:class:`~stem.client.Relay` is a wrapper for :class:`~stem.socket.RelaySocket`,
providing higher level functions in much the same way as our
:class:`~stem.control.Controller` wraps :class:`~stem.socket.ControlSocket`.

.. versionadded:: 1.7.0

.. data:: PackType (enum)

  Unsigned `struct.pack format
  <https://docs.python.org/2/library/struct.html#format-characters>` for
  network-order fields.

  ====================  ===========
  PackType              Description
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

PackType = enum.Enum(
  ('CHAR', '!B'),       # 1 byte
  ('SHORT', '!H'),      # 2 bytes
  ('LONG', '!L'),       # 4 bytes
  ('LONG_LONG', '!Q'),  # 8 bytes
)


class CellAttributes(collections.namedtuple('CellAttributes', ['name', 'value', 'fixed_size', 'for_circuit'])):
  """
  Metadata for cells tor will accept on its ORPort.

  :var str name: name of the cell type
  :var int value: integer value of the command on the wire
  :var bool fixed_size: **True** if cells have a fixed length,
    **False** if variable
  :var bool for_circuit: **True** if command is for a circuit,
    **False** otherwise
  """


CELL_ATTR = (
  CellAttributes('PADDING', 0, True, False),              # Padding                  (section 7.2)
  CellAttributes('CREATE', 1, True, True),                # Create a circuit         (section 5.1)
  CellAttributes('CREATED', 2, True, True),               # Acknowledge create       (section 5.1)
  CellAttributes('RELAY', 3, True, True),                 # End-to-end data          (section 5.5 and 6)
  CellAttributes('DESTROY', 4, True, True),               # Stop using a circuit     (section 5.4)
  CellAttributes('CREATE_FAST', 5, True, True),           # Create a circuit, no PK  (section 5.1)
  CellAttributes('CREATED_FAST', 6, True, True),          # Circuit created, no PK   (section 5.1)
  CellAttributes('VERSIONS', 7, False, False),            # Negotiate proto version  (section 4)
  CellAttributes('NETINFO', 8, True, False),              # Time and address info    (section 4.5)
  CellAttributes('RELAY_EARLY', 9, True, True),           # End-to-end data; limited (section 5.6)
  CellAttributes('CREATE2', 10, True, True),              # Extended CREATE cell     (section 5.1)
  CellAttributes('CREATED2', 11, True, True),             # Extended CREATED cell    (section 5.1)
  CellAttributes('PADDING_NEGOTIATE', 12, True, False),   # Padding negotiation      (section 7.2)
  CellAttributes('VPADDING', 128, False, False),          # Variable-length padding  (section 7.2)
  CellAttributes('CERTS', 129, False, False),             # Certificates             (section 4.2)
  CellAttributes('AUTH_CHALLENGE', 130, False, False),    # Challenge value          (section 4.3)
  CellAttributes('AUTHENTICATE', 131, False, False),      # Client authentication    (section 4.5)
  CellAttributes('AUTHORIZE', 132, False, False),         # Client authorization     (not yet used)
)


class Relay(object):
  """
  Connection with a `Tor relay's ORPort
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_.
  """


def cell_attributes(cell_type):
  """
  Provides attributes of the given cell type.

  :parm str,int cell_type: cell type as either a string or integer

  :raise: **ValueError** if cell type is invalid
  """

  param = 'value' if isinstance(cell_type, int) else 'name'

  for attr in CELL_ATTR:
    if getattr(attr, param) == cell_type:
      return attr

  raise ValueError("'%s' isn't a valid cell type" % cell_type)


def serialize_versions(versions):
  """
  Provides the payload for a series of link versions.

  :param list versions: link versions to serialize

  :returns: **bytes** with a payload for these versions
  """

  return b''.join([struct.pack(PackType.SHORT, v) for v in versions])
