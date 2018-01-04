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


class Cell(collections.namedtuple('Cell', ['name', 'value', 'fixed_size', 'for_circuit'])):
  """
  Metadata for ORPort cells.

  :var str name: name of the cell type
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

    :parm str name: name of the cell type to fetch

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

    :parm int value: value of the cell type to fetch

    :raise: **ValueError** if cell type is invalid
    """

    for cell_type in CELL_TYPES:
      if value == cell_type.value:
        return cell_type

    raise ValueError("'%s' isn't a valid cell value" % value)


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
