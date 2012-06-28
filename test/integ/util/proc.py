"""
Integration tests for stem.util.proc functions against the tor process that we're running.
"""
import os
import socket
import unittest

import test.runner
import stem.socket
import stem.control
import stem.util.proc as proc

class TestProc(unittest.TestCase):
  def test_get_cwd(self):
    """
    Tests the stem.util.proc.get_cwd function.
    """
    
    # Skips test if proc utilities are unavailable on this platform.
    # This is repeated at the beginning of every proc integration test.
    if not proc.is_available:
      test.runner.skip(self, "(Unavailable on this platform)")
      return
    
    runner = test.runner.get_runner()
    
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEquals(tor_cwd, proc.get_cwd(runner_pid))
    
  def test_get_uid(self):
    """
    Tests the stem.util.proc.get_uid function.
    """
    
    if not proc.is_available:
      test.runner.skip(self, "(Unavailable on this platform)")
      return
    
    tor_pid = test.runner.get_runner().get_pid()
    
    self.assertEquals(os.geteuid(), proc.get_uid(tor_pid))
    
  def test_get_memory_usage(self):
    """
    Tests the stem.util.proc.get_memory_usage function.
    """
    
    if not proc.is_available:
      test.runner.skip(self, "(Unavailable on this platform)")
      return
    
    tor_pid = test.runner.get_runner().get_pid()
    res_size, vir_size = (proc.get_memory_usage(tor_pid))
    # Checks if get_memory_usage() is greater than a kilobyte.
    res_bool, vir_bool = res_size > 1024, vir_size > 1024
    
    self.assertTrue(res_bool)
    self.assertTrue(vir_bool)
    
  def test_get_stats(self):
    """
    Tests the stem.util.proc.get_memory_usage function.
    """
    
    if not proc.is_available:
      test.runner.skip(self, "(Unavailable on this platform)")
      return
    
    tor_pid = test.runner.get_runner().get_pid()
    command, utime, stime, start_time = proc.get_stats(tor_pid, 'command', 'utime', 'stime', 'start time')
    
    # Checks if utime and stime are greater than 0.
    utime_bool = utime > 0
    stime_bool = stime > 0
    # Checks if start time is greater than get_system_start_time().
    start_time_bool = start_time > proc.get_system_start_time()
    
    self.assertEquals('tor', command)
    self.assertTrue(utime_bool)
    self.assertTrue(stime_bool)
    self.assertTrue(start_time_bool)
    
  def test_get_connections(self):
    """
    Tests the stem.util.proc.get_connections function.
    
    Checks that get_connections() provides the control connection.
    """
    
    if not proc.is_available:
      test.runner.skip(self, "(Unavailable on this platform)")
      return
    
    tor_pid = test.runner.get_runner().get_pid()
    test.runner.get_runner().get_tor_controller(test.runner.CONTROL_PASSWORD)
    ip_bool, socket_bool = False, False
    for tup in proc.get_connections(tor_pid):
      if '127.0.0.1' in tup:
        ip_bool = True
      if test.runner.CONTROL_PORT in tup:
        socket_bool = True
      if ip_bool and socket_bool:
        continue
    
    self.assertTrue(ip_bool)
    self.assertTrue(socket_bool)
