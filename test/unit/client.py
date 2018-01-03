"""
Unit tests for the stem.client.
"""

import unittest

import stem.client


class TestClient(unittest.TestCase):
  def test_cell_attributes(self):
    attr = stem.client.cell_attributes('NETINFO')

    self.assertEqual('NETINFO', attr.name)
    self.assertEqual(8, attr.value)
    self.assertEqual(True, attr.fixed_length)
    self.assertEqual(False, attr.for_circuit)

    self.assertEqual(10, stem.client.cell_attributes('CREATE2').value)
    self.assertEqual('CREATE2', stem.client.cell_attributes(10).name)

    self.assertRaises(ValueError, stem.client.cell_attributes, 'NOPE')
    self.assertRaises(ValueError, stem.client.cell_attributes, 85)
    self.assertRaises(ValueError, stem.client.cell_attributes, None)
