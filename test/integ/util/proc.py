"""
Integration tests for stem.util.proc functions against the tor process that
we're running.
"""

import os
import unittest

import test.runner

from stem.util import proc


class TestProc(unittest.TestCase):
  def test_get_cwd(self):
    """
    Checks that stem.util.proc.get_cwd matches our tor instance's cwd.
    """

    if not proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return
    elif not test.runner.get_runner().is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    runner = test.runner.get_runner()
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEquals(tor_cwd, proc.get_cwd(runner_pid))

  def test_get_uid(self):
    """
    Checks that stem.util.proc.get_uid matches our tor instance's uid.
    """

    if not proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return

    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(os.geteuid(), proc.get_uid(tor_pid))

  def test_get_memory_usage(self):
    """
    Checks that stem.util.proc.get_memory_usage looks somewhat reasonable.
    """

    if not proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return

    tor_pid = test.runner.get_runner().get_pid()
    res_size, vir_size = proc.get_memory_usage(tor_pid)

    # checks that they're larger than a kilobyte
    self.assertTrue(res_size > 1024)
    self.assertTrue(vir_size > 1024)

  def test_get_stats(self):
    """
    Checks that stem.util.proc.get_stats looks somewhat reasonable.
    """

    if not proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return

    tor_pid = test.runner.get_runner().get_pid()
    command, utime, stime, start_time = proc.get_stats(tor_pid, 'command', 'utime', 'stime', 'start time')

    self.assertEquals('tor', command)
    self.assertTrue(float(utime) > 0)
    self.assertTrue(float(stime) >= 0)
    self.assertTrue(float(start_time) > proc.get_system_start_time())

  def test_get_connections(self):
    """
    Checks for our control port in the stem.util.proc.get_connections output if
    we have one.
    """

    runner = test.runner.get_runner()

    if not proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return
    elif not test.runner.Torrc.PORT in runner.get_options():
      test.runner.skip(self, '(no control port)')
      return
    elif not test.runner.get_runner().is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    # making a controller connection so that we have something to query for
    with runner.get_tor_socket():
      tor_pid = test.runner.get_runner().get_pid()

      for conn in proc.get_connections(tor_pid):
        if ('127.0.0.1', test.runner.CONTROL_PORT) == conn[:2]:
          return

      self.fail()
