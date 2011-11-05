"""
Unit tests for the types.get_entry function.
"""

import unittest
import stem.types

class TestGetEntry(unittest.TestCase):
  """
  Tests the types.get_entry function.
  """
  
  def test_examples(self):
    """
    Checks that the examples from the pydoc are correct.
    """
    
    example_input = 'hello there random person'
    example_result = (None, "hello", "there random person")
    self.assertEquals(stem.types.get_entry(example_input), example_result)
    
    example_input = 'version="0.1.2.3"'
    example_result = ("version", "0.1.2.3", "")
    self.assertEquals(stem.types.get_entry(example_input, True, True), example_result)
    
    example_input = r'"this has a \" and \\ in it" foo=bar more_data'
    example_result = (None, r'this has a " and \ in it', "foo=bar more_data")
    self.assertEquals(stem.types.get_entry(example_input, False, True, True), example_result)

