"""
Tests the stem.process functions with various use cases.
"""

import shutil
import subprocess
import tempfile
import time
import unittest

import stem.prereq
import stem.process
import stem.socket
import stem.util.system
import stem.version
import test.runner

try:
  # added in python 3.3
  from unittest.mock import patch
except ImportError:
  from mock import patch


class TestProcess(unittest.TestCase):
  def setUp(self):
    self.data_directory = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.data_directory)

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

    self.assertEqual('', self.run_tor('--quiet', '--invalid_argument', expect_failure = True))

  def test_launch_tor_with_config(self):
    """
    Exercises launch_tor_with_config.
    """

    if test.runner.only_run_once(self, 'test_launch_tor_with_config'):
      return

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

  def test_with_invalid_config(self):
    """
    Spawn a tor process with a configuration that should make it dead on arrival.
    """

    if test.runner.only_run_once(self, 'test_with_invalid_config'):
      return

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

  def test_launch_tor_with_timeout(self):
    """
    Runs launch_tor where it times out before completing.
    """

    if test.runner.only_run_once(self, 'test_launch_tor_with_timeout'):
      return

    runner = test.runner.get_runner()
    start_time = time.time()
    config = {'SocksPort': '2777', 'DataDirectory': self.data_directory}
    self.assertRaises(OSError, stem.process.launch_tor_with_config, config, runner.get_tor_command(), 100, None, 2)
    runtime = time.time() - start_time

    if not (runtime > 2 and runtime < 3):
      self.fail('Test should have taken 2-3 seconds, took %i instead' % runtime)

  @patch('os.getpid')
  def test_take_ownership_via_pid(self, getpid_mock):
    """
    Checks that the tor process quits after we do if we set take_ownership. To
    test this we spawn a process and trick tor into thinking that it is us.
    """

    if not stem.util.system.is_available('sleep'):
      test.runner.skip(self, "('sleep' command is unavailable)")
      return
    elif test.runner.only_run_once(self, 'test_take_ownership_via_pid'):
      return
    elif test.runner.require_version(self, stem.version.Requirement.TAKEOWNERSHIP):
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

  def test_take_ownership_via_controller(self):
    """
    Checks that the tor process quits after the controller that owns it
    connects, then disconnects..
    """

    if test.runner.only_run_once(self, 'test_take_ownership_via_controller'):
      return
    elif test.runner.require_version(self, stem.version.Requirement.TAKEOWNERSHIP):
      return

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

    if kwargs:
      raise ValueError("Got unexpected keyword arguments: %s" % kwargs)

    args = [test.runner.get_runner().get_tor_command()] + list(args)
    tor_process = subprocess.Popen(args, stdout = subprocess.PIPE)

    stdout = tor_process.communicate()[0]
    exit_status = tor_process.poll()

    if exit_status and not expect_failure:
      self.fail("Didn't expect tor to be able to start when we run: %s\n%s" % (' '.join(args), stdout))
    elif not exit_status and expect_failure:
      self.fail("Tor failed to start when we ran: %s\n%s" % (' '.join(args), stdout))

    return stdout
