"""
Unit tests for the types.ControlLine class.
"""

import unittest
import stem.types

class TestControlLine(unittest.TestCase):
  """
  Tests methods of the types.ControlLine class.
  """
  
  def test_pop_examples(self):
    """
    Checks that the pop method's pydoc examples are correct.
    """
    
    line = stem.types.ControlLine("\"We're all mad here.\" says the grinning cat.")
    self.assertEquals(line.pop(True), "We're all mad here.")
    self.assertEquals(line.pop(), "says")
    self.assertEquals(line.remainder(), "the grinning cat.")
    
    line = stem.types.ControlLine("\"this has a \\\" and \\\\ in it\" foo=bar more_data")
    self.assertEquals(line.pop(True, True), "this has a \" and \\ in it")

