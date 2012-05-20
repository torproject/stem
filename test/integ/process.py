"""
Tests the stem.process functions with various use cases.
"""

import time
import unittest

import stem.socket
import stem.process
import test.runner

class TestProcess(unittest.TestCase):
  def test_launch_tor_with_config(self):
    """
    Exercises launch_tor_with_config.
    """
    
    test.runner.only_run_once(self, "test_launch_tor_with_config")
    
    # Launch tor without a torrc, but with a control port. Confirms that this
    # works by checking that we're still able to access the new instance.
    
    tor_process = stem.process.launch_tor_with_config(
      config = {'SocksPort': '2777', 'ControlPort': '2778'},
      completion_percent = 5
    )
    
    control_socket = None
    try:
      control_socket = stem.socket.ControlPort(control_port = 2778)
      runner = test.runner.get_runner()
      stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())
      
      # exercises the socket
      control_socket.send("GETCONF ControlPort")
      getconf_response = control_socket.recv()
      self.assertEquals("ControlPort=2778", str(getconf_response))
    finally:
      if control_socket: control_socket.close()
      tor_process.kill()
  
  def test_launch_tor_with_timeout(self):
    """
    Runs launch_tor where it times out before completing.
    """
    
    test.runner.only_run_once(self, "test_launch_tor_with_timeout")
    
    start_time = time.time()
    self.assertRaises(OSError, stem.process.launch_tor_with_config, {'SocksPort': '2777'}, "tor", 100, None, 2)
    runtime = time.time() - start_time
    self.assertTrue(runtime > 2 and runtime < 3)

