"""
Unit tests for stem.client.Address.
"""

import collections
import unittest

from stem.client import AddrType, Address

ExpectedAddress = collections.namedtuple('ExpectedAddress', ['type', 'type_int', 'value', 'value_bin'])


class TestAddress(unittest.TestCase):
  def test_constructor(self):
    test_data = (
      ((4, '\x7f\x00\x00\x01'), ExpectedAddress(AddrType.IPv4, 4, '127.0.0.1', '\x7f\x00\x00\x01')),
      ((4, 'aq\x0f\x02'), ExpectedAddress(AddrType.IPv4, 4, '97.113.15.2', 'aq\x0f\x02')),
      ((AddrType.IPv4, '127.0.0.1'), ExpectedAddress(AddrType.IPv4, 4, '127.0.0.1', '\x7f\x00\x00\x01')),
      ((AddrType.IPv4, '97.113.15.2'), ExpectedAddress(AddrType.IPv4, 4, '97.113.15.2', 'aq\x0f\x02')),
    )

    for (addr_type, addr_value), expected in test_data:
      addr = Address(addr_type, addr_value)
      self.assertEqual(expected.type, addr.type)
      self.assertEqual(expected.type_int, addr.type_int)
      self.assertEqual(expected.value, addr.value)
      self.assertEqual(expected.value_bin, addr.value_bin)

  def test_pop_ipv4(self):
    addr, content = Address.pop('\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00')
    self.assertEqual('\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00', content)

    self.assertEqual(AddrType.IPv4, addr.type)
    self.assertEqual(4, addr.type_int)
    self.assertEqual('127.0.0.1', addr.value)
    self.assertEqual('\x7f\x00\x00\x01', addr.value_bin)
