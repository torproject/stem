"""
Unit tests for stem.client.datatype.LinkProtocol.
"""

import unittest

from stem.client.datatype import Size, LinkProtocol


class TestLinkProtocol(unittest.TestCase):
  def test_invalid_type(self):
    self.assertRaises(ValueError, LinkProtocol, 'hello')

  def test_attributes(self):
    protocol = LinkProtocol(1)
    self.assertEqual(1, protocol.version)
    self.assertEqual(Size.SHORT, protocol.circ_id_size)
    self.assertEqual(512, protocol.fixed_cell_length)
    self.assertEqual(0x01, protocol.first_circ_id)

    protocol = LinkProtocol(10)
    self.assertEqual(10, protocol.version)
    self.assertEqual(Size.LONG, protocol.circ_id_size)
    self.assertEqual(514, protocol.fixed_cell_length)
    self.assertEqual(0x80000000, protocol.first_circ_id)

  def test_use_as_int(self):
    protocol = LinkProtocol(5)

    self.assertEqual(7, protocol + 2)
    self.assertEqual(3, protocol - 2)
    self.assertEqual(15, protocol * 3)
    self.assertEqual(1, protocol // 3)

  def test_equality(self):
    # LinkProtocols should be comparable with both other LinkProtocols and
    # integers.

    protocol = LinkProtocol(1)

    self.assertEqual(LinkProtocol(1), protocol)
    self.assertNotEqual(LinkProtocol(2), protocol)

    self.assertEqual(1, protocol)
    self.assertNotEqual(2, protocol)
