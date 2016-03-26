"""
Tests the stem.process functions with various use cases.
"""

import binascii
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
import unittest

import stem.prereq
import stem.process
import stem.socket
import stem.util.str_tools
import stem.util.system
import stem.util.tor_tools
import stem.version
import test.runner

from test.runner import (
  require_controller,
  require_version,
  only_run_once,
)

try:
  # added in python 3.3
  from unittest.mock import patch, Mock
except ImportError:
  from mock import patch, Mock

BASIC_RELAY_TORRC = """\
ORPort 6000
ExtORPort 6001
Nickname stemIntegTest
ExitPolicy reject *:*
PublishServerDescriptor 0
DataDirectory %s
"""


class TestProcess(unittest.TestCase):
  def setUp(self):
    self.data_directory = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.data_directory)

  @require_controller
  def test_version_argument(self):
    """
    Check that 'tor --version' matches 'GETINFO version'.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual('Tor version %s.\n' % controller.get_version(), self.run_tor('--version'))

  def test_help_argument(self):
    """
    Check that 'tor --help' provides the expected output.
    """

    help_output = self.run_tor('--help')

    self.assertTrue(help_output.startswith('Copyright (c) 2001'))
    self.assertTrue(help_output.endswith('tor -f <torrc> [args]\nSee man page for options, or https://www.torproject.org/ for documentation.\n'))

    # should be an alias for 'tor -h'

    self.assertEqual(help_output, self.run_tor('-h'))

  def test_quiet_argument(self):
    """
    Check that we don't provide anything on stdout when running 'tor --quiet'.
    """

    self.assertEqual('', self.run_tor('--quiet', '--invalid_argument', 'true', expect_failure = True))

  def test_hush_argument(self):
    """
    Check that we only get warnings and errors when running 'tor --hush'.
    """

    output = self.run_tor('--hush', '--invalid_argument', expect_failure = True)
    self.assertTrue("[warn] Command-line option '--invalid_argument' with no value. Failing." in output)
    self.assertTrue('[err] Reading config failed--see warnings above.' in output)

    output = self.run_tor('--hush', '--invalid_argument', 'true', expect_failure = True)
    self.assertTrue("[warn] Failed to parse/validate config: Unknown option 'invalid_argument'.  Failing." in output)
    self.assertTrue('[err] Reading config failed--see warnings above.' in output)

  def test_hash_password(self):
    """
    Hash a controller password. It's salted so can't assert that we get a
    particular value. Also, tor's output is unnecessarily verbose so including
    hush to cut it down.
    """

    output = self.run_tor('--hush', '--hash-password', 'my_password')
    self.assertTrue(re.match('^16:[0-9A-F]{58}\n$', output))

    # I'm not gonna even pretend to understand the following. Ported directly
    # from tor's test_cmdline_args.py.

    if stem.prereq.is_python_3():
      output_hex = binascii.a2b_hex(stem.util.str_tools._to_bytes(output).strip()[3:])
      salt, how, hashed = output_hex[:8], output_hex[8], output_hex[9:]
    else:
      output_hex = binascii.a2b_hex(output.strip()[3:])
      salt, how, hashed = output_hex[:8], ord(output_hex[8]), output_hex[9:]

    count = (16 + (how & 15)) << ((how >> 4) + 6)
    stuff = salt + b'my_password'
    repetitions = count // len(stuff) + 1
    inp = (stuff * repetitions)[:count]

    self.assertEqual(hashlib.sha1(inp).digest(), hashed)

  def test_hash_password_requires_argument(self):
    """
    Check that 'tor --hash-password' balks if not provided with something to
    hash.
    """

    output = self.run_tor('--hash-password', expect_failure = True)
    self.assertTrue("[warn] Command-line option '--hash-password' with no value. Failing." in output)
    self.assertTrue('[err] Reading config failed--see warnings above.' in output)

  def test_dump_config_argument(self):
    """
    Exercises our 'tor --dump-config' arugments.
    """

    short_output = self.run_tor('--dump-config', 'short', with_torrc = True)
    non_builtin_output = self.run_tor('--dump-config', 'non-builtin', with_torrc = True)
    full_output = self.run_tor('--dump-config', 'full', with_torrc = True)
    self.run_tor('--dump-config', 'invalid_option', with_torrc = True, expect_failure = True)

    torrc_contents = [line for line in test.runner.get_runner().get_torrc_contents().splitlines() if not line.startswith('#')]

    self.assertEqual(sorted(torrc_contents), sorted(short_output.strip().splitlines()))
    self.assertEqual(sorted(torrc_contents), sorted(non_builtin_output.strip().splitlines()))

    for line in torrc_contents:
      self.assertTrue(line in full_output)

  def test_validate_config_argument(self):
    """
    Exercises our 'tor --validate-config' argument.
    """

    valid_output = self.run_tor('--verify-config', with_torrc = True)
    self.assertTrue('Configuration was valid\n' in valid_output)

    self.run_tor('--verify-config', '-f', __file__, expect_failure = True)

  def test_list_fingerprint_argument(self):
    """
    Exercise our 'tor --list-fingerprint' argument.
    """

    # This command should only work with a relay (which our test instance isn't).

    output = self.run_tor('--list-fingerprint', with_torrc = True, expect_failure = True)
    self.assertTrue("Clients don't have long-term identity keys. Exiting." in output)

    torrc_path = os.path.join(self.data_directory, 'torrc')

    with open(torrc_path, 'w') as torrc_file:
      torrc_file.write(BASIC_RELAY_TORRC % self.data_directory)

    output = self.run_tor('--list-fingerprint', '-f', torrc_path)
    nickname, fingerprint_with_spaces = output.splitlines()[-1].split(' ', 1)
    fingerprint = fingerprint_with_spaces.replace(' ', '')

    self.assertEqual('stemIntegTest', nickname)
    self.assertEqual(49, len(fingerprint_with_spaces))
    self.assertTrue(stem.util.tor_tools.is_valid_fingerprint(fingerprint))

    with open(os.path.join(self.data_directory, 'fingerprint')) as fingerprint_file:
      expected = 'stemIntegTest %s\n' % fingerprint
      self.assertEqual(expected, fingerprint_file.read())

  def test_list_torrc_options_argument(self):
    """
    Exercise our 'tor --list-torrc-options' argument.
    """

    output = self.run_tor('--list-torrc-options')
    self.assertTrue(len(output.splitlines()) > 50)
    self.assertTrue(output.splitlines()[0] <= 'AccountingMax')
    self.assertTrue('UseBridges' in output)
    self.assertTrue('SocksPort' in output)

  @patch('re.compile', Mock(side_effect = KeyboardInterrupt('nope')))
  def test_no_orphaned_process(self):
    """
    Check that when an exception arises in the middle of spawning tor that we
    don't leave a lingering process.
    """

    # We don't need to actually run tor for this test. Rather, any process will
    # do the trick. Picking sleep so this'll clean itself up if our test fails.

    mock_tor_process = subprocess.Popen(['sleep', '60'])

    with patch('subprocess.Popen', Mock(return_value = mock_tor_process)):
      try:
        stem.process.launch_tor()
        self.fail("tor shoudn't have started")
      except KeyboardInterrupt as exc:
        if os.path.exists('/proc/%s' % mock_tor_process.pid):
          self.fail('launch_tor() left a lingering tor process')

        self.assertEqual('nope', str(exc))

  def test_torrc_arguments(self):
    """
    Pass configuration options on the commandline.
    """

    torrc_path = os.path.join(self.data_directory, 'torrc')

    with open(torrc_path, 'w') as torrc_file:
      torrc_file.write(BASIC_RELAY_TORRC % self.data_directory)

    config_args = [
      '+ORPort', '9003',  # appends an extra ORPort
      'SocksPort', '9090',
      '/ExtORPort',  # drops our ExtORPort
      '/TransPort',  # drops a port we didn't originally have
      '+ControlPort', '9005',  # appends a ControlPort where we didn't have any before
    ]

    output = self.run_tor('-f', torrc_path, '--dump-config', 'short', *config_args)
    result = [line for line in output.splitlines() if not line.startswith('DataDirectory')]

    expected = [
      'ControlPort 9005',
      'ExitPolicy reject *:*',
      'Nickname stemIntegTest',
      'ORPort 6000',
      'ORPort 9003',
      'PublishServerDescriptor 0',
      'SocksPort 9090',
    ]

    self.assertEqual(expected, result)

  @require_version(stem.version.Requirement.TORRC_VIA_STDIN)
  def test_torrc_arguments_via_stdin(self):
    """
    Pass configuration options via stdin.
    """

    torrc = BASIC_RELAY_TORRC % self.data_directory
    output = self.run_tor('-f', '-', '--dump-config', 'short', stdin = torrc)
    self.assertEqual(sorted(torrc.splitlines()), sorted(output.splitlines()))

  def test_with_missing_torrc(self):
    """
    Provide a torrc path that doesn't exist.
    """

    output = self.run_tor('-f', '/path/that/really/shouldnt/exist', '--verify-config', expect_failure = True)
    self.assertTrue('[warn] Unable to open configuration file "/path/that/really/shouldnt/exist".' in output)
    self.assertTrue('[err] Reading config failed--see warnings above.' in output)

    output = self.run_tor('-f', '/path/that/really/shouldnt/exist', '--verify-config', '--ignore-missing-torrc')
    self.assertTrue('[notice] Configuration file "/path/that/really/shouldnt/exist" not present, using reasonable defaults.' in output)
    self.assertTrue('Configuration was valid' in output)

  @only_run_once
  @patch('stem.version.get_system_tor_version', Mock(return_value = stem.version.Version('0.0.0.1')))
  def test_launch_tor_with_config_via_file(self):
    """
    Exercises launch_tor_with_config when we write a torrc to disk.
    """

    # Launch tor without a torrc, but with a control port. Confirms that this
    # works by checking that we're still able to access the new instance.

    runner = test.runner.get_runner()
    tor_process = stem.process.launch_tor_with_config(
      tor_cmd = runner.get_tor_command(),
      config = {
        'SocksPort': '2777',
        'ControlPort': '2778',
        'DataDirectory': self.data_directory,
      },
      completion_percent = 5
    )

    control_socket = None
    try:
      control_socket = stem.socket.ControlPort(port = 2778)
      stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())

      # exercises the socket
      control_socket.send('GETCONF ControlPort')
      getconf_response = control_socket.recv()
      self.assertEqual('ControlPort=2778', str(getconf_response))
    finally:
      if control_socket:
        control_socket.close()

      tor_process.kill()
      tor_process.wait()

  @only_run_once
  @require_version(stem.version.Requirement.TORRC_VIA_STDIN)
  def test_launch_tor_with_config_via_stdin(self):
    """
    Exercises launch_tor_with_config when we provide our torrc via stdin.
    """

    runner = test.runner.get_runner()
    tor_process = stem.process.launch_tor_with_config(
      tor_cmd = runner.get_tor_command(),
      config = {
        'SocksPort': '2777',
        'ControlPort': '2778',
        'DataDirectory': self.data_directory,
      },
      completion_percent = 5
    )

    control_socket = None
    try:
      control_socket = stem.socket.ControlPort(port = 2778)
      stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())

      # exercises the socket
      control_socket.send('GETCONF ControlPort')
      getconf_response = control_socket.recv()
      self.assertEqual('ControlPort=2778', str(getconf_response))
    finally:
      if control_socket:
        control_socket.close()

      tor_process.kill()
      tor_process.wait()

  @only_run_once
  def test_with_invalid_config(self):
    """
    Spawn a tor process with a configuration that should make it dead on arrival.
    """

    # Set the same SocksPort and ControlPort, this should fail with...
    #
    #   [warn] Failed to parse/validate config: Failed to bind one of the listener ports.
    #   [err] Reading config failed--see warnings above.

    try:
      stem.process.launch_tor_with_config(
        tor_cmd = test.runner.get_runner().get_tor_command(),
        config = {
          'SocksPort': '2777',
          'ControlPort': '2777',
          'DataDirectory': self.data_directory,
        },
      )
      self.fail("We should abort when there's an identical SocksPort and ControlPort")
    except OSError as exc:
      self.assertEqual('Process terminated: Failed to bind one of the listener ports.', str(exc))

  @only_run_once
  def test_launch_tor_with_timeout(self):
    """
    Runs launch_tor where it times out before completing.
    """

    runner = test.runner.get_runner()
    start_time = time.time()
    config = {'SocksPort': '2777', 'DataDirectory': self.data_directory}
    self.assertRaises(OSError, stem.process.launch_tor_with_config, config, runner.get_tor_command(), 100, None, 2)
    runtime = time.time() - start_time

    if not (runtime > 2 and runtime < 3):
      self.fail('Test should have taken 2-3 seconds, took %0.1f instead' % runtime)

  @require_version(stem.version.Requirement.TAKEOWNERSHIP)
  @only_run_once
  @patch('os.getpid')
  def test_take_ownership_via_pid(self, getpid_mock):
    """
    Checks that the tor process quits after we do if we set take_ownership. To
    test this we spawn a process and trick tor into thinking that it is us.
    """

    if not stem.util.system.is_available('sleep'):
      test.runner.skip(self, "('sleep' command is unavailable)")
      return

    sleep_process = subprocess.Popen(['sleep', '60'])
    getpid_mock.return_value = str(sleep_process.pid)

    tor_process = stem.process.launch_tor_with_config(
      tor_cmd = test.runner.get_runner().get_tor_command(),
      config = {
        'SocksPort': '2777',
        'ControlPort': '2778',
        'DataDirectory': self.data_directory,
      },
      completion_percent = 5,
      take_ownership = True,
    )

    # Kill the sleep command. Tor should quit shortly after.

    sleep_process.kill()
    sleep_process.communicate()

    # tor polls for the process every fifteen seconds so this may take a
    # while...

    for seconds_waited in range(30):
      if tor_process.poll() == 0:
        return  # tor exited

      time.sleep(1)

    self.fail("tor didn't quit after the process that owned it terminated")

  @require_version(stem.version.Requirement.TAKEOWNERSHIP)
  @only_run_once
  def test_take_ownership_via_controller(self):
    """
    Checks that the tor process quits after the controller that owns it
    connects, then disconnects..
    """

    tor_process = stem.process.launch_tor_with_config(
      tor_cmd = test.runner.get_runner().get_tor_command(),
      config = {
        'SocksPort': '2777',
        'ControlPort': '2778',
        'DataDirectory': self.data_directory,
      },
      completion_percent = 5,
      take_ownership = True,
    )

    # We're the controlling process. Just need to connect then disconnect.

    controller = stem.control.Controller.from_port(port = 2778)
    controller.authenticate()
    controller.close()

    # give tor a few seconds to quit
    for seconds_waited in range(5):
      if tor_process.poll() == 0:
        return  # tor exited

      time.sleep(1)

    self.fail("tor didn't quit after the controller that owned it disconnected")

  def run_tor(self, *args, **kwargs):
    # python doesn't allow us to have individual keyword arguments when there's
    # an arbitrary number of positional arguments, so explicitly checking

    expect_failure = kwargs.pop('expect_failure', False)
    with_torrc = kwargs.pop('with_torrc', False)
    stdin = kwargs.pop('stdin', None)

    if kwargs:
      raise ValueError('Got unexpected keyword arguments: %s' % kwargs)

    if with_torrc:
      args = ['-f', test.runner.get_runner().get_torrc_path()] + list(args)

    args = [test.runner.get_runner().get_tor_command()] + list(args)
    tor_process = subprocess.Popen(args, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

    if stdin:
      tor_process.stdin.write(stem.util.str_tools._to_bytes(stdin))

    stdout = tor_process.communicate()[0]
    exit_status = tor_process.poll()

    if exit_status and not expect_failure:
      self.fail("Tor failed to start when we ran: %s\n%s" % (' '.join(args), stdout))
    elif not exit_status and expect_failure:
      self.fail("Didn't expect tor to be able to start when we run: %s\n%s" % (' '.join(args), stdout))

    return stem.util.str_tools._to_unicode(stdout) if stem.prereq.is_python_3() else stdout
