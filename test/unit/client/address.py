"""
Unit tests for stem.client.Address.
"""

import unittest

from stem.client import Address


class TestAddress(unittest.TestCase):
  def test_ipv4(self):
    addr, content = Address.pop('\x04\x04\x7f\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00')
    self.assertEqual('\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00', content)

    self.assertEqual('IPv4', addr.type)
    self.assertEqual(4, addr.type_int)
    self.assertEqual('127.0.0.1', addr.value)
    self.assertEqual('\x7f\x00\x00\x01', addr.value_bin)
