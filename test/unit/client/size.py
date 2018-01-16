"""
Unit tests for stem.client.Size.
"""

import re
import unittest

from stem.client import Size


class TestSize(unittest.TestCase):
  def test_attributes(self):
    self.assertEqual('CHAR', Size.CHAR.name)
    self.assertEqual('!B', Size.CHAR.format)

    self.assertEqual(1, Size.CHAR.size)
    self.assertEqual(2, Size.SHORT.size)
    self.assertEqual(4, Size.LONG.size)
    self.assertEqual(8, Size.LONG_LONG.size)

  def test_pack(self):
    self.assertEqual('\x12', Size.CHAR.pack(18))
    self.assertEqual('\x00\x12', Size.SHORT.pack(18))
    self.assertEqual('\x00\x00\x00\x12', Size.LONG.pack(18))
    self.assertEqual('\x00\x00\x00\x00\x00\x00\x00\x12', Size.LONG_LONG.pack(18))

    self.assertRaisesRegexp(ValueError, 'Size.pack encodes an integer, but was a str', Size.CHAR.pack, 'hi')

    bad_size = Size('BAD_SIZE', 1, '!H')
    self.assertRaisesRegexp(ValueError, re.escape("'\\x00\\x12' is the wrong size for a BAD_SIZE field"), bad_size.pack, 18)

  def test_unpack(self):
    self.assertEqual(18, Size.CHAR.unpack('\x12'))
    self.assertEqual(18, Size.SHORT.unpack('\x00\x12'))
    self.assertEqual(18, Size.LONG.unpack('\x00\x00\x00\x12'))
    self.assertEqual(18, Size.LONG_LONG.unpack('\x00\x00\x00\x00\x00\x00\x00\x12'))

    self.assertEqual(ord('a'), Size.CHAR.unpack('a'))
    self.assertEqual(24930, Size.SHORT.unpack('ab'))

    self.assertRaisesRegexp(ValueError, re.escape("'\\x00\\x12' is the wrong size for a CHAR field"), Size.CHAR.unpack, '\x00\x12')

  def test_pop(self):
    self.assertEqual((18, ''), Size.CHAR.pop('\x12'))

    self.assertEqual((0, '\x12'), Size.CHAR.pop('\x00\x12'))
    self.assertEqual((18, ''), Size.SHORT.pop('\x00\x12'))

    self.assertRaisesRegexp(ValueError, "'' is the wrong size for a CHAR field", Size.CHAR.pop, '')
    self.assertRaisesRegexp(ValueError, re.escape("'\\x12' is the wrong size for a SHORT field"), Size.SHORT.pop, '\x12')
