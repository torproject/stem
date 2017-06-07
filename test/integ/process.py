"""
Tests the stem.process functions with various use cases.
"""

import binascii
import hashlib
import os
import random
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest

import stem.prereq
import stem.process
import stem.socket
import stem.util.str_tools
import stem.util.system
import stem.util.test_tools
import stem.util.tor_tools
import stem.version
import test
import test.require

from contextlib import contextmanager
from stem.util.test_tools import asynchronous

try:
  # added in python 3.3
  from unittest.mock import patch, Mock
except ImportError:
  from mock import patch, Mock

BASIC_RELAY_TORRC = """\
SocksPort 9089
ExtORPort 6001
Nickname stemIntegTest
ExitPolicy reject *:*
PublishServerDescriptor 0
DataDirectory %s
"""


def random_port():
  return str(random.randint(1024, 65536))


@contextmanager
def tmp_directory():
  tmp_dir = tempfile.mkdtemp()

  try:
    yield tmp_dir
  finally:
    shutil.rmtree(tmp_dir)


def run_tor(tor_cmd, *args, **kwargs):
  # python doesn't allow us to have individual keyword arguments when there's
  # an arbitrary number of positional arguments, so explicitly checking

  expect_failure = kwargs.pop('expect_failure', False)
  with_torrc = kwargs.pop('with_torrc', False)
  stdin = kwargs.pop('stdin', None)

  if kwargs:
    raise ValueError('Got unexpected keyword arguments: %s' % kwargs)

  with tmp_directory() as data_directory:
    if with_torrc:
      torrc_path = os.path.join(data_directory, 'torrc')

      with open(torrc_path, 'w') as torrc_file:
        torrc_file.write(BASIC_RELAY_TORRC % data_directory)

      args = ['-f', torrc_path] + list(args)

    args = [tor_cmd] + list(args)
    tor_process = subprocess.Popen(args, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

    if stdin:
      tor_process.stdin.write(stem.util.str_tools._to_bytes(stdin))

    stdout = tor_process.communicate()[0]
    exit_status = tor_process.poll()

    if exit_status and not expect_failure:
      raise AssertionError("Tor failed to start when we ran: %s\n%s" % (' '.join(args), stdout))
    elif not exit_status and expect_failure:
      raise AssertionError("Didn't expect tor to be able to start when we run: %s\n%s" % (' '.join(args), stdout))

    return stem.util.str_tools._to_unicode(stdout) if stem.prereq.is_python_3() else stdout


class TestProcess(unittest.TestCase):
  @staticmethod
  def run_tests(tor_cmd):
    for func, async_test in stem.util.test_tools.ASYNC_TESTS.items():
      if func.startswith('test.integ.process.'):
        async_test.run(tor_cmd)

  @asynchronous
  def test_version_argument(tor_cmd):
    """
    Check that 'tor --version' matches 'GETINFO version'.
    """

    version_output = run_tor(tor_cmd, '--version')

    if 'Tor version %s.\n' % test.tor_version() != version_output:
      raise AssertionError('Unexpected response: %s' % version_output)

  @asynchronous
  def test_help_argument(tor_cmd):
    """
    Check that 'tor --help' provides the expected output.
    """

    help_output = run_tor(tor_cmd, '--help')

    if not help_output.startswith('Copyright (c) 2001') or not help_output.endswith('tor -f <torrc> [args]\nSee man page for options, or https://www.torproject.org/ for documentation.\n'):
      raise AssertionError("Help output didn't have the expected strings: %s" % help_output)

    if help_output != run_tor(tor_cmd, '-h'):
      raise AssertionError("'tor -h' should simply be an alias for 'tor --help'")

  @asynchronous
  def test_quiet_argument(tor_cmd):
    """
    Check that we don't provide anything on stdout when running 'tor --quiet'.
    """

    if '' != run_tor(tor_cmd, '--quiet', '--invalid_argument', 'true', expect_failure = True):
      raise AssertionError('No output should be provided with the --quiet argument')

  @asynchronous
  def test_hush_argument(tor_cmd):
    """
    Check that we only get warnings and errors when running 'tor --hush'.
    """

    output = run_tor(tor_cmd, '--hush', '--invalid_argument', expect_failure = True)

    if "[warn] Command-line option '--invalid_argument' with no value. Failing." not in output:
      raise AssertionError('Unexpected response: %s' % output)

    output = run_tor(tor_cmd, '--hush', '--invalid_argument', 'true', expect_failure = True)

    if "[warn] Failed to parse/validate config: Unknown option 'invalid_argument'.  Failing." not in output:
      raise AssertionError('Unexpected response: %s' % output)

  @asynchronous
  def test_hash_password(tor_cmd):
    """
    Hash a controller password. It's salted so can't assert that we get a
    particular value. Also, tor's output is unnecessarily verbose so including
    hush to cut it down.
    """

    output = run_tor(tor_cmd, '--hush', '--hash-password', 'my_password').splitlines()[-1]

    if not re.match('^16:[0-9A-F]{58}$', output):
      raise AssertionError("Unexpected response from 'tor --hash-password my_password': %s" % output)

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

    if hashlib.sha1(inp).digest() != hashed:
      raise AssertionError('Password hash not what we expected (%s rather than %s)' % (hashlib.sha1(inp).digest(), hashed))

  @asynchronous
  def test_hash_password_requires_argument(tor_cmd):
    """
    Check that 'tor --hash-password' balks if not provided with something to
    hash.
    """

    output = run_tor(tor_cmd, '--hash-password', expect_failure = True)

    if "[warn] Command-line option '--hash-password' with no value. Failing." not in output:
      raise AssertionError("'tor --hash-password' should require an argument")

  @asynchronous
  def test_dump_config_argument(tor_cmd):
    """
    Exercises our 'tor --dump-config' arugments.
    """

    short_output = run_tor(tor_cmd, '--dump-config', 'short', with_torrc = True)
    non_builtin_output = run_tor(tor_cmd, '--dump-config', 'non-builtin', with_torrc = True)
    full_output = run_tor(tor_cmd, '--dump-config', 'full', with_torrc = True)
    run_tor(tor_cmd, '--dump-config', 'invalid_option', with_torrc = True, expect_failure = True)

    if 'Nickname stemIntegTest' not in short_output:
      raise AssertionError("Dumping short config options didn't include our nickname: %s" % short_output)

    if 'Nickname stemIntegTest' not in non_builtin_output:
      raise AssertionError("Dumping non-builtin config options didn't include our nickname: %s" % non_builtin_output)

    if 'Nickname stemIntegTest' not in full_output:
      raise AssertionError("Dumping full config options didn't include our nickname: %s" % full_output)

  @asynchronous
  def test_validate_config_argument(tor_cmd):
    """
    Exercises our 'tor --validate-config' argument.
    """

    valid_output = run_tor(tor_cmd, '--verify-config', with_torrc = True)

    if 'Configuration was valid\n' not in valid_output:
      raise AssertionError('Expected configuration to be valid')

    run_tor(tor_cmd, '--verify-config', '-f', __file__, expect_failure = True)

  @asynchronous
  def test_list_fingerprint_argument(tor_cmd):
    """
    Exercise our 'tor --list-fingerprint' argument.
    """

    # This command should only work with a relay (which our test instance isn't).

    output = run_tor(tor_cmd, '--list-fingerprint', with_torrc = True, expect_failure = True)

    if "Clients don't have long-term identity keys. Exiting." not in output:
      raise AssertionError('Should fail to start due to lacking an ORPort')

    with tmp_directory() as data_directory:
      torrc_path = os.path.join(data_directory, 'torrc')

      with open(torrc_path, 'w') as torrc_file:
        torrc_file.write(BASIC_RELAY_TORRC % data_directory + '\nORPort 6954')

      output = run_tor(tor_cmd, '--list-fingerprint', '-f', torrc_path)
      nickname, fingerprint_with_spaces = output.splitlines()[-1].split(' ', 1)
      fingerprint = fingerprint_with_spaces.replace(' ', '')

      if 'stemIntegTest' != nickname:
        raise AssertionError("Nickname should be 'stemIntegTest': %s" % nickname)
      elif 49 != len(fingerprint_with_spaces):
        raise AssertionError('There should be 49 components in our fingerprint: %i' % len(fingerprint_with_spaces))
      elif not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
        raise AssertionError('We should have a valid fingerprint: %s' % fingerprint)

      with open(os.path.join(data_directory, 'fingerprint')) as fingerprint_file:
        expected = 'stemIntegTest %s\n' % fingerprint
        fingerprint_file_content = fingerprint_file.read()

        if expected != fingerprint_file_content:
          raise AssertionError('Unexpected fingerprint file: %s' % fingerprint_file_content)

  @asynchronous
  def test_list_torrc_options_argument(tor_cmd):
    """
    Exercise our 'tor --list-torrc-options' argument.
    """

    output = run_tor(tor_cmd, '--list-torrc-options')

    if len(output.splitlines()) < 50:
      raise AssertionError("'tor --list-torrc-options' should have numerous entries, but only had %i" % len(output.splitlines()))
    elif 'UseBridges' not in output or 'SocksPort' not in output:
      raise AssertionError("'tor --list-torrc-options' didn't have options we expect")

  @test.require.command('sleep')
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

  @asynchronous
  def test_torrc_arguments(tor_cmd):
    """
    Pass configuration options on the commandline.
    """

    with tmp_directory() as data_directory:
      torrc_path = os.path.join(data_directory, 'torrc')

      with open(torrc_path, 'w') as torrc_file:
        torrc_file.write(BASIC_RELAY_TORRC % data_directory)

      config_args = [
        '+SocksPort', '9090',  # append an extra SocksPort
        '/ExtORPort',  # drops our ExtORPort
        '/TransPort',  # drops a port we didn't originally have
        '+ControlPort', '9005',  # appends a ControlPort where we didn't have any before
      ]

      output = run_tor(tor_cmd, '-f', torrc_path, '--dump-config', 'short', *config_args)
      result = [line for line in output.splitlines() if not line.startswith('DataDirectory')]

      expected = [
        'ControlPort 9005',
        'ExitPolicy reject *:*',
        'Nickname stemIntegTest',
        'PublishServerDescriptor 0',
        'SocksPort 9089',
        'SocksPort 9090',
      ]

      if expected != result:
        raise AssertionError("Unexpected output from 'tor -f torrc --dump-config short': %s" % result)

  @asynchronous
  def test_torrc_arguments_via_stdin(tor_cmd):
    """
    Pass configuration options via stdin.
    """

    if test.tor_version() < stem.version.Requirement.TORRC_VIA_STDIN:
      raise stem.util.test_tools.SkipTest('(requires )' % stem.version.Requirement.TORRC_VIA_STDIN)

    with tmp_directory() as data_directory:
      torrc = BASIC_RELAY_TORRC % data_directory
      output = run_tor(tor_cmd, '-f', '-', '--dump-config', 'short', stdin = torrc)

      if sorted(torrc.splitlines()) != sorted(output.splitlines()):
        raise AssertionError("Unexpected output from 'tor -f - --dump-config short': %s" % output)

  @asynchronous
  def test_with_missing_torrc(tor_cmd):
    """
    Provide a torrc path that doesn't exist.
    """

    output = run_tor(tor_cmd, '-f', '/path/that/really/shouldnt/exist', '--verify-config', expect_failure = True)

    if '[warn] Unable to open configuration file "/path/that/really/shouldnt/exist".' not in output:
      raise AssertionError('Tor refuse to read a non-existant torrc file')

    output = run_tor(tor_cmd, '-f', '/path/that/really/shouldnt/exist', '--verify-config', '--ignore-missing-torrc')

    if '[notice] Configuration file "/path/that/really/shouldnt/exist" not present, using reasonable defaults.' not in output:
      raise AssertionError('Missing torrc should be allowed with --ignore-missing-torrc')

  @asynchronous
  def test_can_run_multithreaded(tor_cmd):
    """
    Our launch_tor() function uses signal to support its timeout argument.
    This only works in the main thread so ensure we give a useful message when
    it isn't.
    """

    with tmp_directory() as data_directory:
      # Tries running tor in another thread with the given timeout argument. This
      # issues an invalid torrc so we terminate right away if we get to the point
      # of actually invoking tor.
      #
      # Returns None if launching tor is successful, and otherwise returns the
      # exception we raised.

      def launch_async_with_timeout(timeout_arg):
        raised_exc = [None]

        def short_launch():
          try:
            stem.process.launch_tor_with_config({'SocksPort': 'invalid', 'DataDirectory': data_directory}, tor_cmd, 100, None, timeout_arg)
          except Exception as exc:
            raised_exc[0] = exc

        t = threading.Thread(target = short_launch)
        t.start()
        t.join()

        if 'Invalid SocksPort' in str(raised_exc[0]):
          return None  # got to the point of invoking tor
        else:
          return raised_exc[0]

      exc = launch_async_with_timeout(0.5)

      if type(exc) != OSError or str(exc) != 'Launching tor with a timeout can only be done in the main thread':
        raise AssertionError("Exception isn't what we expected: %s" % exc)

      # We should launch successfully if no timeout is specified or we specify it
      # to be 'None'.

      if launch_async_with_timeout(None) is not None:
        raise AssertionError('Launching tor without a timeout should be successful')

      if launch_async_with_timeout(stem.process.DEFAULT_INIT_TIMEOUT) is not None:
        raise AssertionError('Launching tor with the default timeout should be successful')

  @asynchronous
  def test_launch_tor_with_config_via_file(tor_cmd):
    """
    Exercises launch_tor_with_config when we write a torrc to disk.
    """

    with tmp_directory() as data_directory:
      control_port = random_port()
      control_socket, tor_process = None, None

      try:
        # Launch tor without a torrc, but with a control port. Confirms that this
        # works by checking that we're still able to access the new instance.

        with patch('stem.version.get_system_tor_version', Mock(return_value = stem.version.Version('0.0.0.1'))):
          tor_process = stem.process.launch_tor_with_config(
            tor_cmd = tor_cmd,
            config = {
              'SocksPort': random_port(),
              'ControlPort': control_port,
              'DataDirectory': data_directory,
            },
            completion_percent = 5
          )

        control_socket = stem.socket.ControlPort(port = int(control_port))
        stem.connection.authenticate(control_socket)

        # exercises the socket
        control_socket.send('GETCONF ControlPort')
        getconf_response = control_socket.recv()

        if 'ControlPort=%s' % control_port != str(getconf_response):
          raise AssertionError('Expected tor to report its ControlPort as %s but was: %s' % (control_port, getconf_response))
      finally:
        if control_socket:
          control_socket.close()

        if tor_process:
          tor_process.kill()
          tor_process.wait()

  @asynchronous
  def test_launch_tor_with_config_via_stdin(tor_cmd):
    """
    Exercises launch_tor_with_config when we provide our torrc via stdin.
    """

    if test.tor_version() < stem.version.Requirement.TORRC_VIA_STDIN:
      raise stem.util.test_tools.SkipTest('(requires )' % stem.version.Requirement.TORRC_VIA_STDIN)

    with tmp_directory() as data_directory:
      control_port = random_port()
      control_socket, tor_process = None, None

      try:
        tor_process = stem.process.launch_tor_with_config(
          tor_cmd = tor_cmd,
          config = {
            'SocksPort': random_port(),
            'ControlPort': control_port,
            'DataDirectory': data_directory,
          },
          completion_percent = 5
        )

        control_socket = stem.socket.ControlPort(port = int(control_port))
        stem.connection.authenticate(control_socket)

        # exercises the socket
        control_socket.send('GETCONF ControlPort')
        getconf_response = control_socket.recv()

        if 'ControlPort=%s' % control_port != str(getconf_response):
          raise AssertionError('Expected tor to report its ControlPort as %s but was: %s' % (control_port, getconf_response))
      finally:
        if control_socket:
          control_socket.close()

        if tor_process:
          tor_process.kill()
          tor_process.wait()

  @asynchronous
  def test_with_invalid_config(tor_cmd):
    """
    Spawn a tor process with a configuration that should make it dead on arrival.
    """

    # Set the same SocksPort and ControlPort, this should fail with...
    #
    #   [warn] Failed to parse/validate config: Failed to bind one of the listener ports.
    #   [err] Reading config failed--see warnings above.

    with tmp_directory() as data_directory:
      both_ports = random_port()

      try:
        stem.process.launch_tor_with_config(
          tor_cmd = tor_cmd,
          config = {
            'SocksPort': both_ports,
            'ControlPort': both_ports,
            'DataDirectory': data_directory,
          },
        )

        raise AssertionError('Tor should fail to launch')
      except OSError as exc:
        if str(exc) != 'Process terminated: Failed to bind one of the listener ports.':
          raise AssertionError('Unexpected error response from tor: %s' % exc)

  @asynchronous
  def test_launch_tor_with_timeout(tor_cmd):
    """
    Runs launch_tor where it times out before completing.
    """

    with tmp_directory() as data_directory:
      start_time = time.time()

      try:
        stem.process.launch_tor_with_config(
          tor_cmd = tor_cmd,
          timeout = 0.05,
          config = {
            'SocksPort': random_port(),
            'DataDirectory': data_directory,
          },
        )

        raise AssertionError('Tor should fail to launch')
      except OSError:
        runtime = time.time() - start_time

        if not (runtime > 0.05 and runtime < 1):
          raise AssertionError('Test should have taken 0.05-1 seconds, took %0.1f instead' % runtime)

  @asynchronous
  def test_take_ownership_via_pid(tor_cmd):
    """
    Checks that the tor process quits after we do if we set take_ownership. To
    test this we spawn a process and trick tor into thinking that it is us.
    """

    if not stem.util.system.is_available('sleep'):
      raise stem.util.test_tools.SkipTest('(sleep unavailable)')
    elif test.tor_version() < stem.version.Requirement.TAKEOWNERSHIP:
      raise stem.util.test_tools.SkipTest('(requires )' % stem.version.Requirement.TAKEOWNERSHIP)

    with tmp_directory() as data_directory:
      sleep_process = subprocess.Popen(['sleep', '60'])

      tor_process = stem.process.launch_tor_with_config(
        tor_cmd = tor_cmd,
        config = {
          'SocksPort': random_port(),
          'ControlPort': random_port(),
          'DataDirectory': data_directory,
          '__OwningControllerProcess': str(sleep_process.pid),
        },
        completion_percent = 5,
      )

      # Kill the sleep command. Tor should quit shortly after.

      sleep_process.kill()
      sleep_process.communicate()

      # tor polls for the process every fifteen seconds so this may take a
      # while...
      #
      #   https://trac.torproject.org/projects/tor/ticket/21281

      start_time = time.time()

      while time.time() - start_time < 30:
        if tor_process.poll() == 0:
          return  # tor exited

        time.sleep(0.01)

      raise AssertionError("tor didn't quit after the process that owned it terminated")

  @asynchronous
  def test_take_ownership_via_controller(tor_cmd):
    """
    Checks that the tor process quits after the controller that owns it
    connects, then disconnects..
    """

    if test.tor_version() < stem.version.Requirement.TAKEOWNERSHIP:
      raise stem.util.test_tools.SkipTest('(requires )' % stem.version.Requirement.TAKEOWNERSHIP)

    with tmp_directory() as data_directory:
      control_port = random_port()

      tor_process = stem.process.launch_tor_with_config(
        tor_cmd = tor_cmd,
        config = {
          'SocksPort': random_port(),
          'ControlPort': control_port,
          'DataDirectory': data_directory,
        },
        completion_percent = 5,
        take_ownership = True,
      )

      # We're the controlling process. Just need to connect then disconnect.

      controller = stem.control.Controller.from_port(port = int(control_port))
      controller.authenticate()
      controller.close()

      # give tor a few seconds to quit
      start_time = time.time()

      while time.time() - start_time < 5:
        if tor_process.poll() == 0:
          return  # tor exited

        time.sleep(0.01)

      raise AssertionError("tor didn't quit after the controller that owned it disconnected")
