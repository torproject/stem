"""
Unit tests for the stem.client.cell.
"""

import struct
import unittest

from stem.client import Pack
from stem.client.cell import Cell


class TestCell(unittest.TestCase):
  def test_by_name(self):
    cell = Cell.by_name('NETINFO')
    self.assertEqual('NETINFO', cell.name)
    self.assertEqual(8, cell.value)
    self.assertEqual(True, cell.fixed_size)
    self.assertEqual(False, cell.for_circuit)

    self.assertRaises(ValueError, Cell.by_name, 'NOPE')
    self.assertRaises(ValueError, Cell.by_name, 85)
    self.assertRaises(ValueError, Cell.by_name, None)

  def test_by_value(self):
    cell = Cell.by_value(8)
    self.assertEqual('NETINFO', cell.name)
    self.assertEqual(8, cell.value)
    self.assertEqual(True, cell.fixed_size)
    self.assertEqual(False, cell.for_circuit)

    self.assertRaises(ValueError, Cell.by_value, 'NOPE')
    self.assertRaises(ValueError, Cell.by_value, 85)
    self.assertRaises(ValueError, Cell.by_value, None)

  def test_pack(self):
    version_payload = struct.pack(Pack.SHORT, 2)

    # basic link v2 and v4 VERSIONS cell

    self.assertEqual('\x00\x00\x07\x00\x02\x00\x02', Cell.pack('VERSIONS', 2, version_payload))
    self.assertEqual('\x00\x00\x00\x00\x07\x00\x02\x00\x02', Cell.pack('VERSIONS', 4, version_payload))

    self.assertRaisesRegexp(ValueError, "'NOPE' isn't a valid cell type", Cell.pack, 'NOPE', 2, version_payload)
    self.assertRaisesRegexp(ValueError, "VERSIONS cells don't concern circuits, circ_id is unused", Cell.pack, 'VERSIONS', 2, version_payload, circ_id = 5)
    self.assertRaisesRegexp(ValueError, 'RELAY_EARLY cells require a circ_id', Cell.pack, 'RELAY_EARLY', 2, version_payload)
