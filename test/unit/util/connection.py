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
    
    self.assertTrue(stem.util.connection.is_valid_ip_address("0.0.0.0"))
    self.assertTrue(stem.util.connection.is_valid_ip_address("1.2.3.4"))
    self.assertTrue(stem.util.connection.is_valid_ip_address("192.168.0.1"))
    self.assertTrue(stem.util.connection.is_valid_ip_address("255.255.255.255"))
    
    self.assertFalse(stem.util.connection.is_valid_ip_address("0.0.00.0"))
    self.assertFalse(stem.util.connection.is_valid_ip_address("0.0.0"))
    self.assertFalse(stem.util.connection.is_valid_ip_address("1.2.3.256"))
    self.assertFalse(stem.util.connection.is_valid_ip_address("1.2.3.-1"))
    self.assertFalse(stem.util.connection.is_valid_ip_address("0.0.0.a"))
    self.assertFalse(stem.util.connection.is_valid_ip_address("a.b.c.d"))

