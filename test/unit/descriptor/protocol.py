"""
Unit tessts for the stem.descriptor.ProtocolSupport class.
"""

import unittest

from stem.descriptor import Protocol, ProtocolSupport


class TestProtocol(unittest.TestCase):
  def test_parsing(self):
    expected = [
      Protocol(name = 'Desc', min_version = 1, max_version = 1),
      Protocol(name = 'Link', min_version = 1, max_version = 4),
      Protocol(name = 'Microdesc', min_version = 1, max_version = 1),
      Protocol(name = 'Relay', min_version = 1, max_version = 2),
    ]

    self.assertEqual(expected, list(ProtocolSupport('pr', 'Desc=1 Link=1-4 Microdesc=1 Relay=1-2')))

  def test_parse_with_no_mapping(self):
    try:
      ProtocolSupport('pr', 'Desc Link=1-4')
      self.fail('Did not raise expected exception')
    except ValueError as exc:
      self.assertEqual("Protocol entires are expected to be a series of 'key=value' pairs but was: pr Desc Link=1-4", str(exc))

  def test_parse_with_non_int_version(self):
    try:
      ProtocolSupport('pr', 'Desc=hi Link=1-4')
      self.fail('Did not raise expected exception')
    except ValueError as exc:
      self.assertEqual('Protocol values should be a number or number range, but was: pr Desc=hi Link=1-4', str(exc))

  def test_is_supported(self):
    protocol = ProtocolSupport('pr', 'Desc=1 Link=2-4 Microdesc=1 Relay=1-2')
    self.assertFalse(protocol.is_supported('NoSuchProtocol'))
    self.assertFalse(protocol.is_supported('Desc', 2))
    self.assertTrue(protocol.is_supported('Desc'))
    self.assertTrue(protocol.is_supported('Desc', 1))

    self.assertFalse(protocol.is_supported('Link', 1))
    self.assertTrue(protocol.is_supported('Link', 2))
    self.assertTrue(protocol.is_supported('Link', 3))
    self.assertTrue(protocol.is_supported('Link', 4))
    self.assertFalse(protocol.is_supported('Link', 5))
