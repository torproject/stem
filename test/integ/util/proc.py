"""
Integration tests for stem.util.proc functions against the tor process that
we're running.
"""

import os
import unittest

import test.require
import test.runner

from stem.util import proc
from stem.util.test_tools import async_test


class TestProc(unittest.TestCase):
  @test.require.proc
  @test.require.ptrace
  def test_cwd(self):
    """
    Checks that stem.util.proc.cwd matches our tor instance's cwd.
    """

    runner = test.runner.get_runner()
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEqual(tor_cwd, proc.cwd(runner_pid))

  @test.require.proc
  def test_uid(self):
    """
    Checks that stem.util.proc.uid matches our tor instance's uid.
    """

    tor_pid = test.runner.get_runner().get_pid()
    self.assertEqual(os.geteuid(), proc.uid(tor_pid))

  @test.require.proc
  def test_memory_usage(self):
    """
    Checks that stem.util.proc.memory_usage looks somewhat reasonable.
    """

    tor_pid = test.runner.get_runner().get_pid()
    res_size, vir_size = proc.memory_usage(tor_pid)

    # checks that they're larger than a kilobyte
    self.assertTrue(res_size > 1024)
    self.assertTrue(vir_size > 1024)

  @test.require.proc
  def test_stats(self):
    """
    Checks that stem.util.proc.stats looks somewhat reasonable.
    """

    tor_cmd = test.runner.get_runner().get_tor_command(True)
    tor_pid = test.runner.get_runner().get_pid()
    command, utime, stime, start_time = proc.stats(tor_pid, 'command', 'utime', 'stime', 'start time')

    self.assertEqual(tor_cmd, command)
    self.assertTrue(float(utime) > 0)
    self.assertTrue(float(stime) >= 0)
    self.assertTrue(float(start_time) > proc.system_start_time())

  @test.require.proc
  @test.require.ptrace
  @async_test
  async def test_connections(self):
    """
    Checks for our control port in the stem.util.proc.connections output if
    we have one.
    """

    runner = test.runner.get_runner()

    if test.runner.Torrc.PORT not in runner.get_options():
      self.skiTestp('(no control port)')
      return
    elif not os.access('/proc/net/tcp', os.R_OK) or not os.access('/proc/net/udp', os.R_OK):
      self.skipTest('(proc lacks read permissions)')

    # making a controller connection so that we have something to query for
    async with await runner.get_tor_socket():
      tor_pid = test.runner.get_runner().get_pid()

      for conn in proc.connections(tor_pid):
        if ('127.0.0.1', test.runner.CONTROL_PORT) == conn[:2]:
          return

      self.fail()
