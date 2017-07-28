"""
Integration tests for stem.util.connection functions against the tor process
that we're running.
"""

import unittest

import stem.util.system
import test.require
import test.runner

from stem.util.connection import RESOLVER_COMMAND, Resolver, get_connections, system_resolvers


class TestConnection(unittest.TestCase):
  @test.require.ptrace
  def check_resolver(self, resolver):
    runner = test.runner.get_runner()

    if test.runner.Torrc.PORT not in runner.get_options():
      self.skipTest('(no control port)')
      return
    elif resolver not in system_resolvers():
      self.skipTest('(resolver unavailable on this platform)')
      return

    with runner.get_tor_socket():
      connections = get_connections(resolver, process_pid = runner.get_pid())

      for conn in connections:
        if conn.local_address == '127.0.0.1' and conn.local_port == test.runner.CONTROL_PORT:
          return

      resolver_command = RESOLVER_COMMAND[resolver].format(pid = runner.get_pid())
      resolver_output = stem.util.system.call(resolver_command)

      self.fail('Unable to find our controller connection with %s (%s). Connections found were...\n\n%s\n\nCommand output was...\n\n%s' % (resolver, resolver_command, '\n'.join(map(str, connections)), resolver_output))

  def test_connections_by_proc(self):
    self.check_resolver(Resolver.PROC)

  def test_connections_by_netstat(self):
    self.check_resolver(Resolver.NETSTAT)

  def test_connections_by_windows_netstat(self):
    self.check_resolver(Resolver.NETSTAT_WINDOWS)

  def test_connections_by_ss(self):
    self.check_resolver(Resolver.SS)

  def test_connections_by_lsof(self):
    self.check_resolver(Resolver.LSOF)

  def test_connections_by_bsd_sockstat(self):
    self.check_resolver(Resolver.BSD_SOCKSTAT)

  def test_connections_by_bsd_procstat(self):
    self.check_resolver(Resolver.BSD_PROCSTAT)

  def test_connections_by_bsd_fstat(self):
    self.check_resolver(Resolver.BSD_FSTAT)

  def test_that_we_are_checking_all_resolvers(self):
    # Quick check to confirm that if we add a new Resolver, we include a test
    # for it here.

    recognized_resolvers = (
      Resolver.PROC,
      Resolver.NETSTAT,
      Resolver.NETSTAT_WINDOWS,
      Resolver.SS,
      Resolver.LSOF,
      Resolver.SOCKSTAT,
      Resolver.BSD_SOCKSTAT,
      Resolver.BSD_PROCSTAT,
      Resolver.BSD_FSTAT,
    )

    for resolver in Resolver:
      self.assertTrue(resolver in recognized_resolvers)
