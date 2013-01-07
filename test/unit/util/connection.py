"""
Unit tests for the stem.util.connection functions.
"""

import unittest

import stem.util.connection


class TestConnection(unittest.TestCase):
  def test_is_valid_ip_address(self):
    """
    Checks the is_valid_ip_address function.
    """

    valid_addresses = (
      "0.0.0.0",
      "1.2.3.4",
      "192.168.0.1",
      "255.255.255.255",
    )

    invalid_addresses = (
      "0.0.00.0",
      "0.0.0",
      "1.2.3.256",
      "1.2.3.-1",
      "0.0.0.a",
      "a.b.c.d",
    )

    for address in valid_addresses:
      self.assertTrue(stem.util.connection.is_valid_ip_address(address))

    for address in invalid_addresses:
      self.assertFalse(stem.util.connection.is_valid_ip_address(address))

  def test_is_valid_ipv6_address(self):
    """
    Checks the is_valid_ipv6_address function.
    """

    valid_addresses = (
      "fe80:0000:0000:0000:0202:b3ff:fe1e:8329",
      "fe80:0:0:0:202:b3ff:fe1e:8329",
      "fe80::202:b3ff:fe1e:8329",
      "::",
    )

    invalid_addresses = (
      "fe80:0000:0000:0000:0202:b3ff:fe1e:829g",
      "fe80:0000:0000:0000:0202:b3ff:fe1e: 8329",
      "2001:db8::aaaa::1",
      ":::",
      ":",
      "",
    )

    for address in valid_addresses:
      self.assertTrue(stem.util.connection.is_valid_ipv6_address(address))

    for address in invalid_addresses:
      self.assertFalse(stem.util.connection.is_valid_ipv6_address(address))

  def test_is_valid_port(self):
    """
    Checks the is_valid_port function.
    """

    valid_ports = (1, "1", 1234, "1234", 65535, "65535")
    invalid_ports = (0, "0", 65536, "65536", "abc", "*", " 15", "01")

    for port in valid_ports:
      self.assertTrue(stem.util.connection.is_valid_port(port))

    for port in invalid_ports:
      self.assertFalse(stem.util.connection.is_valid_port(port))

    self.assertTrue(stem.util.connection.is_valid_port(0, allow_zero = True))
    self.assertTrue(stem.util.connection.is_valid_port("0", allow_zero = True))

  def test_expand_ipv6_address(self):
    """
    Checks the expand_ipv6_address function.
    """

    test_values = {
      "2001:db8::ff00:42:8329": "2001:0db8:0000:0000:0000:ff00:0042:8329",
      "::": "0000:0000:0000:0000:0000:0000:0000:0000",
      "::1": "0000:0000:0000:0000:0000:0000:0000:0001",
      "1::1": "0001:0000:0000:0000:0000:0000:0000:0001",
    }

    for test_arg, expected in test_values.items():
      self.assertEquals(expected, stem.util.connection.expand_ipv6_address(test_arg))

    self.assertRaises(ValueError, stem.util.connection.expand_ipv6_address, "127.0.0.1")

  def test_get_mask(self):
    """
    Checks the get_mask function.
    """

    self.assertEquals("255.255.255.255", stem.util.connection.get_mask(32))
    self.assertEquals("255.255.255.248", stem.util.connection.get_mask(29))
    self.assertEquals("255.255.254.0", stem.util.connection.get_mask(23))
    self.assertEquals("0.0.0.0", stem.util.connection.get_mask(0))

    self.assertRaises(ValueError, stem.util.connection.get_mask, -1)
    self.assertRaises(ValueError, stem.util.connection.get_mask, 33)

  def test_get_masked_bits(self):
    """
    Checks the get_masked_bits function.
    """

    self.assertEquals(32, stem.util.connection.get_masked_bits("255.255.255.255"))
    self.assertEquals(29, stem.util.connection.get_masked_bits("255.255.255.248"))
    self.assertEquals(23, stem.util.connection.get_masked_bits("255.255.254.0"))
    self.assertEquals(0, stem.util.connection.get_masked_bits("0.0.0.0"))

    self.assertRaises(ValueError, stem.util.connection.get_masked_bits, "blarg")
    self.assertRaises(ValueError, stem.util.connection.get_masked_bits, "255.255.0.255")

  def test_get_mask_ipv6(self):
    """
    Checks the get_mask_ipv6 function.
    """

    self.assertEquals("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", stem.util.connection.get_mask_ipv6(128))
    self.assertEquals("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFE:0000", stem.util.connection.get_mask_ipv6(111))
    self.assertEquals("0000:0000:0000:0000:0000:0000:0000:0000", stem.util.connection.get_mask_ipv6(0))

    self.assertRaises(ValueError, stem.util.connection.get_mask_ipv6, -1)
    self.assertRaises(ValueError, stem.util.connection.get_mask, 129)

  def test_get_address_binary(self):
    """
    Checks the get_address_binary function.
    """

    test_values = {
      "0.0.0.0": "00000000000000000000000000000000",
      "1.2.3.4": "00000001000000100000001100000100",
      "127.0.0.1": "01111111000000000000000000000001",
      "255.255.255.255": "11111111111111111111111111111111",
      "::": "0" * 128,
      "::1": ("0" * 127) + "1",
      "1::1": "0000000000000001" + ("0" * 111) + "1",
      "2001:db8::ff00:42:8329": "00100000000000010000110110111000000000000000000000000000000000000000000000000000111111110000000000000000010000101000001100101001",
    }

    for test_arg, expected in test_values.items():
      self.assertEquals(expected, stem.util.connection.get_address_binary(test_arg))

    self.assertRaises(ValueError, stem.util.connection.get_address_binary, "")
    self.assertRaises(ValueError, stem.util.connection.get_address_binary, "blarg")
