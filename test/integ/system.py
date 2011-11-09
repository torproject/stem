"""
Unit tests for the util.system functions in the context of a tor process.
"""

import unittest
import test.runner

from stem.util import system

class TestSystemFunctions(unittest.TestCase):
  """
  Tests the util.system functions against the tor process that we're running.
  """
  
  def test_is_available(self):
    """
    Checks the util.system.is_available function.
    """
    
    # since we're running tor it would be kinda sad if this didn't detect it
    self.assertTrue(system.is_available("tor"))
    
    # but it would be kinda weird if this did...
    self.assertFalse(system.is_available("blarg_and_stuff"))
  
  def test_is_running(self):
    """
    Checks the util.system.is_running function.
    """
    
    self.assertTrue(system.is_running("tor"))
    self.assertFalse(system.is_running("blarg_and_stuff"))

  def test_get_pid(self):
    """
    Checks the util.system.get_pid function.
    """
    
    runner = test.runner.get_runner()
    self.assertEquals(runner.get_pid(), system.get_pid("tor", runner.get_control_port()))
    self.assertEquals(None, system.get_pid("blarg_and_stuff"))
  
  def test_get_bsd_jail_id(self):
    """
    Exercises the util.system.get_bsd_jail_id function, running through the
    failure case (since I'm not on BSD I can't really test this function
    properly).
    """
    
    self.assertEquals(0, system.get_bsd_jail_id(99999))

