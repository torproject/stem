"""
Unit tests for the types in stem.client.
"""

import re
import unittest

from stem.client import Address, Size


class TestClientTypes(unittest.TestCase):
  def test_address_ipv4(self):
    addr, content = Address.pop('\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00')
    self.assertEqual('\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00', content)

    self.assertEqual('IPv4', addr.type)
    self.assertEqual(4, addr.type_int)
    self.assertEqual('127.0.0.1', addr.value)
    self.assertEqual('\x7f\x00\x00\x01', addr.value_bin)

  def test_size_attributes(self):
    self.assertEqual('CHAR', Size.CHAR.name)
    self.assertEqual('!B', Size.CHAR.format)

    self.assertEqual(1, Size.CHAR.size)
    self.assertEqual(2, Size.SHORT.size)
    self.assertEqual(4, Size.LONG.size)
    self.assertEqual(8, Size.LONG_LONG.size)

  def test_size_pack(self):
    self.assertEqual('\x12', Size.CHAR.pack(18))
    self.assertEqual('\x00\x12', Size.SHORT.pack(18))
    self.assertEqual('\x00\x00\x00\x12', Size.LONG.pack(18))
    self.assertEqual('\x00\x00\x00\x00\x00\x00\x00\x12', Size.LONG_LONG.pack(18))

    self.assertRaisesRegexp(ValueError, 'Size.pack encodes an integer, but was a str', Size.CHAR.pack, 'hi')

    bad_size = Size('BAD_SIZE', 1, '!H')
    self.assertRaisesRegexp(ValueError, re.escape("'\\x00\\x12' is the wrong size for a BAD_SIZE field"), bad_size.pack, 18)

  def test_size_unpack(self):
    self.assertEqual(18, Size.CHAR.unpack('\x12'))
    self.assertEqual(18, Size.SHORT.unpack('\x00\x12'))
    self.assertEqual(18, Size.LONG.unpack('\x00\x00\x00\x12'))
    self.assertEqual(18, Size.LONG_LONG.unpack('\x00\x00\x00\x00\x00\x00\x00\x12'))

    self.assertEqual(ord('a'), Size.CHAR.unpack('a'))
    self.assertEqual(24930, Size.SHORT.unpack('ab'))

    self.assertRaisesRegexp(ValueError, re.escape("'\\x00\\x12' is the wrong size for a CHAR field"), Size.CHAR.unpack, '\x00\x12')

  def test_size_pop(self):
    self.assertEqual((18, ''), Size.CHAR.pop('\x12'))

    self.assertEqual((0, '\x12'), Size.CHAR.pop('\x00\x12'))
    self.assertEqual((18, ''), Size.SHORT.pop('\x00\x12'))

    self.assertRaisesRegexp(ValueError, "'' is the wrong size for a CHAR field", Size.CHAR.pop, '')
    self.assertRaisesRegexp(ValueError, re.escape("'\\x12' is the wrong size for a SHORT field"), Size.SHORT.pop, '\x12')
