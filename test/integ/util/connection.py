"""
Integration tests for stem.util.connection functions against the tor process
that we're running.
"""

import unittest

import stem
import stem.util.connection
import stem.util.system
import test.require
import test.runner

from stem.util.connection import Resolver

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib


class TestConnection(unittest.TestCase):
  @test.require.ptrace
  def check_resolver(self, resolver):
    runner = test.runner.get_runner()

    if test.runner.Torrc.PORT not in runner.get_options():
      self.skipTest('(no control port)')
      return
    elif resolver not in stem.util.connection.system_resolvers():
      self.skipTest('(resolver unavailable on this platform)')
      return

    with runner.get_tor_socket():
      connections = stem.util.connection.get_connections(resolver, process_pid = runner.get_pid())

      for conn in connections:
        if conn.local_address == '127.0.0.1' and conn.local_port == test.runner.CONTROL_PORT:
          return

      resolver_command = stem.util.connection.RESOLVER_COMMAND[resolver].format(pid = runner.get_pid())
      resolver_output = stem.util.system.call(resolver_command)

      self.fail('Unable to find our controller connection with %s (%s). Connections found were...\n\n%s\n\nCommand output was...\n\n%s' % (resolver, resolver_command, '\n'.join(map(str, connections)), resolver_output))

  @test.require.only_run_once
  @test.require.online
  def test_download(self):
    response = stem.util.connection.download('https://collector.torproject.org/index/index.json')
    self.assertTrue(b'"path":"https://collector.torproject.org"' in response)

  @test.require.only_run_once
  @test.require.online
  def test_download_failure(self):
    try:
      stem.util.connection.download('https://no.such.testing.url')
      self.fail('expected a stem.DownloadFailed to be raised')
    except stem.DownloadFailed as exc:
      self.assertEqual('Failed to download from https://no.such.testing.url (URLError): Name or service not known', str(exc))
      self.assertEqual('https://no.such.testing.url', exc.url)
      self.assertEqual('Name or service not known', exc.error.reason.strerror)
      self.assertEqual(urllib.URLError, type(exc.error))

  def test_connections_by_proc(self):
    self.check_resolver(Resolver.PROC)

  def test_connections_by_netstat(self):
    self.check_resolver(Resolver.NETSTAT)

  def test_connections_by_windows_netstat(self):
    self.check_resolver(Resolver.NETSTAT_WINDOWS)

  def test_connections_by_ss(self):
    try:
      self.check_resolver(Resolver.SS)
    except (IOError, OSError):
      self.skipTest('(ticket 27479)')

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
