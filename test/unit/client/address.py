"""
Unit tests for stem.client.Address.
"""

import collections
import re
import unittest

from stem.client import AddrType, Address

ExpectedAddress = collections.namedtuple('ExpectedAddress', ['type', 'type_int', 'value', 'value_bin'])


class TestAddress(unittest.TestCase):
  def test_constructor(self):
    test_data = (
      ((4, '\x7f\x00\x00\x01'), ExpectedAddress(AddrType.IPv4, 4, '127.0.0.1', '\x7f\x00\x00\x01')),
      ((4, 'aq\x0f\x02'), ExpectedAddress(AddrType.IPv4, 4, '97.113.15.2', 'aq\x0f\x02')),
      ((6, ' \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)'), ExpectedAddress(AddrType.IPv6, 6, '2001:0db8:0000:0000:0000:ff00:0042:8329', ' \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)')),
      ((AddrType.IPv4, '127.0.0.1'), ExpectedAddress(AddrType.IPv4, 4, '127.0.0.1', '\x7f\x00\x00\x01')),
      ((AddrType.IPv4, '97.113.15.2'), ExpectedAddress(AddrType.IPv4, 4, '97.113.15.2', 'aq\x0f\x02')),
      ((AddrType.IPv6, '2001:0db8:0000:0000:0000:ff00:0042:8329'), ExpectedAddress(AddrType.IPv6, 6, '2001:0db8:0000:0000:0000:ff00:0042:8329', ' \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)')),
      ((AddrType.IPv6, '2001:0DB8:AC10:FE01::'), ExpectedAddress(AddrType.IPv6, 6, '2001:0db8:ac10:fe01:0000:0000:0000:0000', ' \x01\r\xb8\xac\x10\xfe\x01\x00\x00\x00\x00\x00\x00\x00\x00')),  # collaped and different case
    )

    for (addr_type, addr_value), expected in test_data:
      addr = Address(addr_type, addr_value)
      self.assertEqual(expected.type, addr.type)
      self.assertEqual(expected.type_int, addr.type_int)
      self.assertEqual(expected.value, addr.value)
      self.assertEqual(expected.value_bin, addr.value_bin)

    self.assertRaisesRegexp(ValueError, re.escape("Packed IPv4 addresses should be four bytes, but was: '\\x7f\\x00'"), Address, 4, '\x7f\x00')
    self.assertRaisesRegexp(ValueError, re.escape("Packed IPv6 addresses should be sixteen bytes, but was: '\\x7f\\x00'"), Address, 6, '\x7f\x00')

  def test_unknown_type(self):
    addr = Address(12, 'hello')
    self.assertEqual(AddrType.UNKNOWN, addr.type)
    self.assertEqual(12, addr.type_int)
    self.assertEqual(None, addr.value)
    self.assertEqual('hello', addr.value_bin)

  def test_packing(self):
    test_data = {
      '\x04\x04\x7f\x00\x00\x01': Address(AddrType.IPv4, '127.0.0.1'),
      '\x06\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)': Address(AddrType.IPv6, '2001:0db8:0000:0000:0000:ff00:0042:8329'),
    }

    for cell_bytes, address in test_data.items():
      self.assertEqual(cell_bytes, address.pack())
      self.assertEqual(address, Address.unpack(cell_bytes))

    addr, content = Address.pop('\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00')
    self.assertEqual('\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00', content)

    self.assertEqual(AddrType.IPv4, addr.type)
    self.assertEqual(4, addr.type_int)
    self.assertEqual('127.0.0.1', addr.value)
    self.assertEqual('\x7f\x00\x00\x01', addr.value_bin)
