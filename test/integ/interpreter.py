"""
Tests invocation of our interpreter.
"""

import os
import tempfile
import unittest

import stem.util.system
import test.require
import test.runner
import test.util

PROMPT_CMD = os.path.join(test.util.STEM_BASE, 'tor-prompt')


def _run_prompt(*args):
  if test.runner.Torrc.SOCKET not in test.runner.get_runner().get_options():
    return stem.util.system.call([PROMPT_CMD, '--interface', test.runner.CONTROL_PORT] + list(args))
  else:
    return stem.util.system.call([PROMPT_CMD, '--socket', test.runner.CONTROL_SOCKET_PATH] + list(args))


class TestInterpreter(unittest.TestCase):
  @test.require.controller
  def test_running_command(self):
    # We'd need to provide the password to stdin. Fine test to add later but
    # not gonna hassle for now.

    if test.runner.Torrc.PASSWORD in test.runner.get_runner().get_options():
      self.skipTest('password auth unsupported')
      return

    expected = ['250-config-file=%s' % test.runner.get_runner().get_torrc_path(), '250 OK']
    self.assertEqual(expected, _run_prompt('--run', 'GETINFO config-file'))

  @test.require.controller
  def test_running_file(self):
    if test.runner.Torrc.PASSWORD in test.runner.get_runner().get_options():
      self.skipTest('password auth unsupported')
      return

    expected = [
      '250-config-file=%s' % test.runner.get_runner().get_torrc_path(),
      '250 OK',
      '',
      '250-version=%s' % test.util.tor_version(),
      '250 OK',
    ]

    with tempfile.NamedTemporaryFile(prefix = 'test_commands.') as tmp:
      tmp.write('GETINFO config-file\nGETINFO version')
      tmp.flush()

      self.assertEqual(expected, _run_prompt('--run', tmp.name))
