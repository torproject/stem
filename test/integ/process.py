"""
Tests the stem.process functions with various use cases.
"""

import os
import time
import signal
import unittest

import stem.prereq
import stem.socket
import stem.process
import test.runner
import stem.util.system

class TestProcess(unittest.TestCase):
  def test_launch_tor_with_config(self):
    """
    Exercises launch_tor_with_config.
    """
    
    if not stem.prereq.is_python_26() and stem.util.system.is_windows():
      test.runner.skip("(unable to kill subprocesses)")
      return
    
    if test.runner.only_run_once(self, "test_launch_tor_with_config"): return
    
    # Launch tor without a torrc, but with a control port. Confirms that this
    # works by checking that we're still able to access the new instance.
    
    runner = test.runner.get_runner()
    tor_process = stem.process.launch_tor_with_config(
      tor_cmd = runner.get_tor_command(),
      config = {'SocksPort': '2777', 'ControlPort': '2778'},
      completion_percent = 5
    )
    
    control_socket = None
    try:
      control_socket = stem.socket.ControlPort(control_port = 2778)
      stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())
      
      # exercises the socket
      control_socket.send("GETCONF ControlPort")
      getconf_response = control_socket.recv()
      self.assertEquals("ControlPort=2778", str(getconf_response))
    finally:
      if control_socket: control_socket.close()
      
      if stem.prereq.is_python_26():
        tor_process.kill()
      elif stem.util.system.is_windows():
        os.kill(tor_process.pid, signal.SIGTERM)
  
  def test_launch_tor_with_timeout(self):
    """
    Runs launch_tor where it times out before completing.
    """
    
    if not stem.prereq.is_python_26() and stem.util.system.is_windows():
      test.runner.skip("(unable to kill subprocesses)")
      return
    
    if test.runner.only_run_once(self, "test_launch_tor_with_timeout"): return
    
    runner = test.runner.get_runner()
    start_time = time.time()
    self.assertRaises(OSError, stem.process.launch_tor_with_config, {'SocksPort': '2777'}, runner.get_tor_command(), 100, None, 2)
    runtime = time.time() - start_time
    
    if not (runtime > 2 and runtime < 3):
      self.fail("Test should have taken 2-3 seconds, took %i instead" % runtime)

