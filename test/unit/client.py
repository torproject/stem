"""
Unit tests for the stem.client.
"""

import unittest

from stem.client import Cell


class TestClient(unittest.TestCase):
  def test_cell_fetching(self):
    cell = Cell.by_name('NETINFO')

    self.assertEqual('NETINFO', cell.name)
    self.assertEqual(8, cell.value)
    self.assertEqual(True, cell.fixed_size)
    self.assertEqual(False, cell.for_circuit)

    self.assertEqual(10, Cell.by_name('CREATE2').value)
    self.assertEqual('CREATE2', Cell.by_value(10).name)

    self.assertRaises(ValueError, Cell.by_name, 'NOPE')
    self.assertRaises(ValueError, Cell.by_value, 'NOPE')
    self.assertRaises(ValueError, Cell.by_name, 85)
    self.assertRaises(ValueError, Cell.by_name, None)
