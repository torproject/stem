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
      self.assertEquals('ControlPort=2778', str(getconf_response))
    finally:
      if control_socket:
        control_socket.close()

      tor_process.kill()
      tor_process.wait()

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

    for seconds_waited in xrange(30):
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
    for seconds_waited in xrange(5):
      if tor_process.poll() == 0:
        return  # tor exited

      time.sleep(1)

    self.fail("tor didn't quit after the controller that owned it disconnected")
