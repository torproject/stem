"""
Unit tests for the stem.util.str_tools functions.
"""

import unittest
from stem.util import str_tools

class TestStrTools(unittest.TestCase):
  def test_to_camel_case(self):
    """
    Checks the to_camel_case() function.
    """
    
    # test the pydoc example
    self.assertEquals("I Like Pepperjack!", str_tools.to_camel_case("I_LIKE_PEPPERJACK!"))
    
    # check a few edge cases
    self.assertEquals("", str_tools.to_camel_case(""))
    self.assertEquals("Hello", str_tools.to_camel_case("hello"))
    self.assertEquals("Hello", str_tools.to_camel_case("HELLO"))
    self.assertEquals("Hello  World", str_tools.to_camel_case("hello__world"))
    self.assertEquals("Hello\tworld", str_tools.to_camel_case("hello\tWORLD"))
    self.assertEquals("Hello\t\tWorld", str_tools.to_camel_case("hello__world", "\t"))
  
  def test_get_size_label(self):
    """
    Checks the get_size_label() function.
    """
    
    # test the pydoc examples
    self.assertEquals('1 MB', str_tools.get_size_label(2000000))
    self.assertEquals('1.02 KB', str_tools.get_size_label(1050, 2))
    self.assertEquals('1.025 Kilobytes', str_tools.get_size_label(1050, 3, True))
  
  def test_get_time_label(self):
    """
    Checks the get_time_label() function.
    """
    
    # test the pydoc examples
    self.assertEquals('2h', str_tools.get_time_label(10000))
    self.assertEquals('1.0 minute', str_tools.get_time_label(61, 1, True))
    self.assertEquals('1.01 minutes', str_tools.get_time_label(61, 2, True))
  
  def test_get_time_labels(self):
    """
    Checks the get_time_labels() function.
    """
    
    # test the pydoc examples
    self.assertEquals(['6m', '40s'], str_tools.get_time_labels(400))
    self.assertEquals(['1 hour', '40 seconds'], str_tools.get_time_labels(3640, True))

