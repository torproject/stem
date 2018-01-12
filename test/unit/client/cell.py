"""
Unit tests for the stem.client.cell.
"""

import unittest

from stem.client.cell import Cell, VersionsCell


class TestCell(unittest.TestCase):
  def test_by_name(self):
    cls = Cell.by_name('NETINFO')
    self.assertEqual('NETINFO', cls.NAME)
    self.assertEqual(8, cls.VALUE)
    self.assertEqual(True, cls.IS_FIXED_SIZE)

    self.assertRaises(ValueError, Cell.by_name, 'NOPE')
    self.assertRaises(ValueError, Cell.by_name, 85)
    self.assertRaises(ValueError, Cell.by_name, None)

  def test_by_value(self):
    cls = Cell.by_value(8)
    self.assertEqual('NETINFO', cls.NAME)
    self.assertEqual(8, cls.VALUE)
    self.assertEqual(True, cls.IS_FIXED_SIZE)

    self.assertRaises(ValueError, Cell.by_value, 'NOPE')
    self.assertRaises(ValueError, Cell.by_value, 85)
    self.assertRaises(ValueError, Cell.by_value, None)

  def test_unpack_not_implemented(self):
    self.assertRaisesRegexp(NotImplementedError, 'Unpacking not yet implemented for AUTHORIZE cells', Cell.unpack, '\x00\x00\x84\x00\x06\x00\x01\x00\x02\x00\x03', 2)

  def test_versions_pack(self):
    self.assertEqual('\x00\x00\x07\x00\x00', VersionsCell.pack([]))
    self.assertEqual('\x00\x00\x07\x00\x02\x00\x01', VersionsCell.pack([1]))
    self.assertEqual('\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03', VersionsCell.pack([1, 2, 3]))

  def test_versions_unpack(self):
    self.assertEqual([], Cell.unpack('\x00\x00\x07\x00\x00', 2).versions)
    self.assertEqual([1], Cell.unpack('\x00\x00\x07\x00\x02\x00\x01', 2).versions)
    self.assertEqual([1, 2, 3], Cell.unpack('\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03', 2).versions)
