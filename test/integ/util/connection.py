"""
Integration tests for stem.util.connection functions against the tor process
that we're running.
"""

import unittest

import test.runner

from stem.util.connection import get_connections, get_system_resolvers


class TestConnection(unittest.TestCase):
  def test_get_connections(self):
    runner = test.runner.get_runner()

    if not test.runner.Torrc.PORT in runner.get_options():
      test.runner.skip(self, '(no control port)')
      return
    elif not test.runner.get_runner().is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    for resolver in get_system_resolvers():
      with runner.get_tor_socket():
        tor_pid = test.runner.get_runner().get_pid()
        connections = get_connections(resolver, process_pid = tor_pid)

        for conn in connections:
          if conn.local_address == '127.0.0.1' and conn.local_port == test.runner.CONTROL_PORT:
            return

        self.fail('Unable to find localhost connection with %s:\n%s' % (resolver, '\n'.join(connections)))
