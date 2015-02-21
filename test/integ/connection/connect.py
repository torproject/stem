"""
Integration tests for the connect_* convenience functions.
"""

import sys
import unittest

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

import stem.connection
import test.runner

from test.runner import require_controller


class TestConnect(unittest.TestCase):
  def setUp(self):
    # prevents the function from printing to the real stdout
    self.original_stdout = sys.stdout
    sys.stdout = StringIO()

  def tearDown(self):
    sys.stdout = self.original_stdout

  @require_controller
  def test_connect(self):
    """
    Basic sanity checks for the connect function.
    """

    runner = test.runner.get_runner()

    control_socket = stem.connection.connect(
      control_port = ('127.0.0.1', test.runner.CONTROL_PORT),
      control_socket = test.runner.CONTROL_SOCKET_PATH,
      password = test.runner.CONTROL_PASSWORD,
      chroot_path = runner.get_chroot(),
      controller = None)

    test.runner.exercise_controller(self, control_socket)

  @require_controller
  def test_connect_port(self):
    """
    Basic sanity checks for the connect_port function.
    """

    runner = test.runner.get_runner()

    control_socket = stem.connection.connect_port(
      port = test.runner.CONTROL_PORT,
      password = test.runner.CONTROL_PASSWORD,
      chroot_path = runner.get_chroot(),
      controller = None)

    if test.runner.Torrc.PORT in runner.get_options():
      test.runner.exercise_controller(self, control_socket)
      control_socket.close()
    else:
      self.assertEqual(control_socket, None)

  @require_controller
  def test_connect_socket_file(self):
    """
    Basic sanity checks for the connect_socket_file function.
    """

    runner = test.runner.get_runner()

    control_socket = stem.connection.connect_socket_file(
      path = test.runner.CONTROL_SOCKET_PATH,
      password = test.runner.CONTROL_PASSWORD,
      chroot_path = runner.get_chroot(),
      controller = None)

    if test.runner.Torrc.SOCKET in runner.get_options():
      test.runner.exercise_controller(self, control_socket)
      control_socket.close()
    else:
      self.assertEqual(control_socket, None)
