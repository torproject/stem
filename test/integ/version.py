"""
Integration tests for tor version parsing.
"""

import unittest

import test.runner
import stem.version

class TestVersion(unittest.TestCase):
  """
  Tests that the stem.version functions can handle the tor instance we're
  running with.
  """
  
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
  
  def test_getinfo_version_parsing(self):
    """
    Issues a 'GETINFO version' query to our test instance and makes sure that
    we can parse it.
    """
    
    runner = test.runner.get_runner()
    
    if not runner.is_accessible():
      self.skipTest("(no connection)")
    
    control_socket = runner.get_tor_socket()
    control_socket.send("GETINFO version")
    version_response = control_socket.recv()
    control_socket.close()
    
    # the getinfo response looks like...
    # 250-version=0.2.1.30
    # 250 OK
    
    tor_version = list(version_response)[0][8:]
    stem.version.Version(tor_version)

