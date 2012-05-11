"""
Tests the stem.process functions with various use cases.
"""

import time
import unittest

import stem.socket
import stem.process
import test.runner

# Tests are target independent. Only run once even if there's multiple targets.

RAN_TESTS = []

class TestProcess(unittest.TestCase):
  def test_launch_tor_options(self):
    """
    Runs launch_tor with options specified via the commandline rather than the
    torrc.
    """
    
    test_name = 'test_launch_tor_options'
    if test_name in RAN_TESTS: self.skipTest("(already ran)")
    
    # Launch tor without a torrc, but with a control port. Confirms that this
    # works by checking that we're still able to access the new instance.
    
    tor_process = stem.process.launch_tor(
      options = {'SocksPort': '2777', 'ControlPort': '2778'},
      torrc_path = stem.process.NO_TORRC,
      completion_percent = 5
    )
    
    control_socket = None
    try:
      control_socket = stem.socket.ControlPort(control_port = 2778)
      runner = test.runner.get_runner()
      stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())
      
      # exercises the socket
      control_socket.send("GETINFO version")
      version_response = control_socket.recv()
      self.assertEquals("version=%s\nOK" % runner.get_tor_version(), str(version_response))
    finally:
      if control_socket: control_socket.close()
      tor_process.kill()
    
    RAN_TESTS.append(test_name)
  
  def test_launch_tor_with_timeout(self):
    """
    Runs launch_tor where it times out before completing.
    """
    
    test_name = 'test_launch_tor_with_timeout'
    if test_name in RAN_TESTS: self.skipTest("(already ran)")
    
    start_time = time.time()
    self.assertRaises(OSError, stem.process.launch_tor, "tor", {'SocksPort': '2777'}, stem.process.NO_TORRC, 100, None, 2)
    runtime = time.time() - start_time
    self.assertTrue(runtime > 2 and runtime < 3)
    
    RAN_TESTS.append(test_name)

