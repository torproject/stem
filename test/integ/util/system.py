"""
Integration tests for the stem.util.system functions in the context of a tor
process.
"""

import os
import unittest

import test.runner
import stem.util.system

class TestSystem(unittest.TestCase):
  """
  Tests the stem.util.system functions against the tor process that we're
  running.
  """
  
  def test_is_available(self):
    """
    Checks the stem.util.system.is_available function.
    """
    
    # since we're running tor it would be kinda sad if this didn't detect it
    self.assertTrue(stem.util.system.is_available("tor"))
    
    # but it would be kinda weird if this did...
    self.assertFalse(stem.util.system.is_available("blarg_and_stuff"))
  
  def test_is_running(self):
    """
    Checks the stem.util.system.is_running function.
    """
    
    self.assertTrue(stem.util.system.is_running("tor"))
    self.assertFalse(stem.util.system.is_running("blarg_and_stuff"))

  def test_get_pid(self):
    """
    Checks the stem.util.system.get_pid function.
    """
    
    runner = test.runner.get_runner()
    self.assertEquals(runner.get_pid(), stem.util.system.get_pid("tor", runner.get_control_port()))
    self.assertEquals(None, stem.util.system.get_pid("blarg_and_stuff"))
  
  def test_get_cwd(self):
    """
    Checks the stem.util.system.get_cwd function.
    """
    
    # tor's pwd will match our process since we started it
    runner = test.runner.get_runner()
    self.assertEquals(os.getcwd(), stem.util.system.get_cwd(runner.get_pid()))
    self.assertEquals(None, stem.util.system.get_cwd(99999, True))
    self.assertRaises(IOError, stem.util.system.get_cwd, 99999, False)
  
  def test_get_bsd_jail_id(self):
    """
    Exercises the stem.util.system.get_bsd_jail_id function, running through
    the failure case (since I'm not on BSD I can't really test this function
    properly).
    """
    
    self.assertEquals(0, stem.util.system.get_bsd_jail_id(99999))

