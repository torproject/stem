"""
Integration tests for stem.util.connection functions against the tor process
that we're running.
"""

import unittest

import test.runner

from stem.util.connection import Resolver, get_connections, system_resolvers
from test.util import skip


class TestConnection(unittest.TestCase):
  def check_resolver(self, resolver):
    runner = test.runner.get_runner()

    if test.runner.Torrc.PORT not in runner.get_options():
      skip(self, '(no control port)')
      return
    elif not runner.is_ptraceable():
      skip(self, '(DisableDebuggerAttachment set)')
      return
    elif resolver not in system_resolvers():
      skip(self, '(resolver unavailable on this platform)')
      return

    with runner.get_tor_socket():
      connections = get_connections(resolver, process_pid = runner.get_pid())

      for conn in connections:
        if conn.local_address == '127.0.0.1' and conn.local_port == test.runner.CONTROL_PORT:
          return

      self.fail('Unable to find localhost connection with %s:\n%s' % (resolver, '\n'.join(connections)))

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

  def test_connections_by_sockstat(self):
    self.check_resolver(Resolver.SOCKSTAT)

  def test_connections_by_bsd_sockstat(self):
    self.check_resolver(Resolver.BSD_SOCKSTAT)

  def test_connections_by_bsd_procstat(self):
    self.check_resolver(Resolver.BSD_PROCSTAT)

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
    )

    for resolver in Resolver:
      self.assertTrue(resolver in recognized_resolvers)
