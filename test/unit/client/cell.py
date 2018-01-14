"""
Unit tests for the stem.client.cell.
"""

import unittest

from stem.client import Certificate
from stem.client.cell import Cell, VersionsCell
from test.unit.client import test_data


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

  def test_unpack_for_new_link(self):
    # TODO: we need to support more cell types before we can test this
    self.assertRaisesRegexp(NotImplementedError, 'Unpacking not yet implemented for AUTH_CHALLENGE cells', Cell.unpack, test_data('new_link_cells'), 2)

  def test_versions_pack(self):
    self.assertEqual('\x00\x00\x07\x00\x00', VersionsCell.pack([]))
    self.assertEqual('\x00\x00\x07\x00\x02\x00\x01', VersionsCell.pack([1]))
    self.assertEqual('\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03', VersionsCell.pack([1, 2, 3]))

  def test_versions_unpack(self):
    test_data = {
      '\x00\x00\x07\x00\x00': [],
      '\x00\x00\x07\x00\x02\x00\x01': [1],
      '\x00\x00\x07\x00\x06\x00\x01\x00\x02\x00\x03': [1, 2, 3],
    }

    for cell_bytes, expected in test_data.items():
      self.assertEqual(expected, Cell.unpack(cell_bytes, 2)[0].versions)

  def test_certs_unpack(self):
    test_data = {
      '\x00\x00\x81\x00\x01\x00': [],
      '\x00\x00\x81\x00\x04\x01\x01\x00\x00': [Certificate(type = 1, value = '')],
      '\x00\x00\x81\x00\x05\x01\x01\x00\x01\x08': [Certificate(type = 1, value = '\x08')],
    }

    for cell_bytes, expected in test_data.items():
      self.assertEqual(expected, Cell.unpack(cell_bytes, 2)[0].certificates)

    # extra bytes after the last certificate should be ignored

    self.assertEqual([Certificate(type = 1, value = '\x08')], Cell.unpack('\x00\x00\x81\x00\x07\x01\x01\x00\x01\x08\x06\x04', 2)[0].certificates)

    # ... but truncated or missing certificates should error

    self.assertRaisesRegexp(ValueError, 'CERTS cell should have a certificate with 3 bytes, but only had 1 remaining', Cell.unpack, '\x00\x00\x81\x00\x05\x01\x01\x00\x03\x08', 2)
    self.assertRaisesRegexp(ValueError, 'CERTS cell indicates it should have 2 certificates, but only contained 1', Cell.unpack, '\x00\x00\x81\x00\x05\x02\x01\x00\x01\x08', 2)
