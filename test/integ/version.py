"""
Tests that the stem.version functions can handle the tor instance we're
running with.
"""

import unittest

import test.runner
import stem.version

class TestVersion(unittest.TestCase):
  def test_get_system_tor_version(self):
    """
    Basic verification checks for the get_system_tor_version() function.
    """
    
    if not stem.util.system.is_available("tor"):
      self.skipTest("(tor isn't in our path)")
    
    # Since tor is in our path we should expect to be able to get the version
    # that way, though this might not belong to our test instance (if we're
    # running against a specific tor binary).
    
    stem.version.get_system_tor_version()
    
    # try running against a command that exists, but isn't tor
    self.assertRaises(IOError, stem.version.get_system_tor_version, "ls")
    
    # try running against a command that doesn't exist
    self.assertRaises(IOError, stem.version.get_system_tor_version, "blarg")
  
  def test_get_system_tor_version_value(self):
    """
    Checks that the get_system_tor_version() provides the same value as our
    test instance provides.
    """
    
    test.runner.require_control(self)
    
    runner = test.runner.get_runner()
    system_tor_version = stem.version.get_system_tor_version(runner.get_tor_command())
    self.assertEquals(runner.get_tor_version(), system_tor_version)
  
  def test_getinfo_version_parsing(self):
    """
    Issues a 'GETINFO version' query to our test instance and makes sure that
    we can parse it.
    """
    
    test.runner.require_control(self)
    
    control_socket = test.runner.get_runner().get_tor_socket()
    control_socket.send("GETINFO version")
    version_response = control_socket.recv()
    control_socket.close()
    
    # the getinfo response looks like...
    # 250-version=0.2.1.30
    # 250 OK
    
    tor_version = list(version_response)[0][8:]
    stem.version.Version(tor_version)

