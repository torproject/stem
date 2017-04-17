"""
Tests invocation of our interpreter.
"""

import os
import tempfile
import unittest

import stem.util.system

import test.runner
import test.util

PROMPT_CMD = os.path.join(test.util.STEM_BASE, 'tor-prompt')


class TestInterpreter(unittest.TestCase):
  def test_running_command(self):
    expected = ['250-config-file=%s' % test.runner.get_runner().get_torrc_path(), '250 OK']
    self.assertEqual(expected, stem.util.system.call([PROMPT_CMD, '--interface', test.runner.CONTROL_PORT, '--run', 'GETINFO config-file']))

  def test_running_file(self):
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

      self.assertEqual(expected, stem.util.system.call([PROMPT_CMD, '--interface', test.runner.CONTROL_PORT, '--run', tmp.name]))
