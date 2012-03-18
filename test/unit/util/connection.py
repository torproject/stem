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

