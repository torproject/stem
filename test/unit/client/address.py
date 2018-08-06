"""
Unit tests for stem.client.Address.
"""

import collections
import unittest

from stem.client.datatype import AddrType, Address

ExpectedAddress = collections.namedtuple('ExpectedAddress', ['type', 'type_int', 'value', 'value_bin'])


class TestAddress(unittest.TestCase):
  def test_enum(self):
    self.assertEqual(('IPv4', 4), AddrType.get(AddrType.IPv4))
    self.assertEqual(('IPv4', 4), AddrType.get(4))

    self.assertEqual(('UNKNOWN', 25), AddrType.get(25))
    self.assertRaisesWith(ValueError, "Invalid enumeration 'boom', options are HOSTNAME, IPv4, IPv6, ERROR_TRANSIENT, ERROR_PERMANENT, UNKNOWN", AddrType.get, 'boom')

  def test_constructor(self):
    test_data = (
      ((4, b'\x7f\x00\x00\x01'), ExpectedAddress(AddrType.IPv4, 4, '127.0.0.1', b'\x7f\x00\x00\x01')),
      ((4, b'aq\x0f\x02'), ExpectedAddress(AddrType.IPv4, 4, '97.113.15.2', b'aq\x0f\x02')),
      ((6, b' \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)'), ExpectedAddress(AddrType.IPv6, 6, '2001:0db8:0000:0000:0000:ff00:0042:8329', b' \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)')),
      ((AddrType.IPv4, '127.0.0.1'), ExpectedAddress(AddrType.IPv4, 4, '127.0.0.1', b'\x7f\x00\x00\x01')),
      ((AddrType.IPv4, '97.113.15.2'), ExpectedAddress(AddrType.IPv4, 4, '97.113.15.2', b'aq\x0f\x02')),
      ((AddrType.IPv6, '2001:0db8:0000:0000:0000:ff00:0042:8329'), ExpectedAddress(AddrType.IPv6, 6, '2001:0db8:0000:0000:0000:ff00:0042:8329', b' \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)')),
      ((AddrType.IPv6, '2001:0DB8:AC10:FE01::'), ExpectedAddress(AddrType.IPv6, 6, '2001:0db8:ac10:fe01:0000:0000:0000:0000', b' \x01\r\xb8\xac\x10\xfe\x01\x00\x00\x00\x00\x00\x00\x00\x00')),  # collaped and different case
    )

    for (addr_type, addr_value), expected in test_data:
      addr = Address(addr_value, addr_type)
      self.assertEqual(expected.type, addr.type)
      self.assertEqual(expected.type_int, addr.type_int)
      self.assertEqual(expected.value, addr.value)
      self.assertEqual(expected.value_bin, addr.value_bin)

    # when an IPv4 or IPv6 address the type is optional

    self.assertEqual(AddrType.IPv4, Address('127.0.0.1').type)
    self.assertEqual(AddrType.IPv6, Address('2001:0DB8:AC10:FE01::').type)

    self.assertRaisesWith(ValueError, "Packed IPv4 addresses should be four bytes, but was: '\\x7f\\x00'", Address, '\x7f\x00', 4)
    self.assertRaisesWith(ValueError, "Packed IPv6 addresses should be sixteen bytes, but was: '\\x7f\\x00'", Address, '\x7f\x00', 6)
    self.assertRaisesWith(ValueError, "'nope' isn't an IPv4 or IPv6 address", Address, 'nope')

  def test_unknown_type(self):
    addr = Address('hello', 12)
    self.assertEqual(AddrType.UNKNOWN, addr.type)
    self.assertEqual(12, addr.type_int)
    self.assertEqual(None, addr.value)
    self.assertEqual('hello', addr.value_bin)

  def test_packing(self):
    test_data = {
      b'\x04\x04\x7f\x00\x00\x01': Address('127.0.0.1'),
      b'\x06\x10 \x01\r\xb8\x00\x00\x00\x00\x00\x00\xff\x00\x00B\x83)': Address('2001:0db8:0000:0000:0000:ff00:0042:8329'),
    }

    for cell_bytes, address in test_data.items():
      self.assertEqual(cell_bytes, address.pack())
      self.assertEqual(address, Address.unpack(cell_bytes))

    addr, content = Address.pop(b'\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00')
    self.assertEqual(b'\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00', content)

    self.assertEqual(AddrType.IPv4, addr.type)
    self.assertEqual(4, addr.type_int)
    self.assertEqual('127.0.0.1', addr.value)
    self.assertEqual(b'\x7f\x00\x00\x01', addr.value_bin)
