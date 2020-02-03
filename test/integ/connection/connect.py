"""
Integration tests for the connect_* convenience functions.
"""

import io
import unittest

import stem.connection
import test.require
import test.runner

from unittest.mock import patch


class TestConnect(unittest.TestCase):
  @test.require.controller
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_connect(self, stdout_mock):
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
    self.assertEqual('', stdout_mock.getvalue())

  @test.require.controller
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_connect_to_socks_port(self, stdout_mock):
    """
    Common user gotcha is connecting to the SocksPort or ORPort rather than the
    ControlPort. Testing that connecting to the SocksPort errors in a
    reasonable way.
    """

    runner = test.runner.get_runner()

    control_socket = stem.connection.connect(
      control_port = ('127.0.0.1', test.runner.SOCKS_PORT),
      chroot_path = runner.get_chroot(),
      controller = None)

    self.assertEqual(None, control_socket)
    self.assertEqual('Please check in your torrc that 1112 is the ControlPort. Maybe you\nconfigured it to be the ORPort or SocksPort instead?\n', stdout_mock.getvalue())
