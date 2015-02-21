"""
Integration tests for the stem.response.protocolinfo.ProtocolInfoResponse class
and related functions.
"""

import unittest

import stem.connection
import stem.socket
import stem.util.system
import stem.version
import test.runner

from test.runner import require_controller
from test.integ.util.system import filter_system_call

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch


class TestProtocolInfo(unittest.TestCase):
  @require_controller
  def test_parsing(self):
    """
    Makes a PROTOCOLINFO query and processes the response for our control
    connection.
    """

    control_socket = test.runner.get_runner().get_tor_socket(False)
    control_socket.send('PROTOCOLINFO 1')
    protocolinfo_response = control_socket.recv()
    stem.response.convert('PROTOCOLINFO', protocolinfo_response)
    control_socket.close()

    # according to the control spec the following _could_ differ or be
    # undefined but if that actually happens then it's gonna make people sad

    self.assertEqual(1, protocolinfo_response.protocol_version)
    self.assertNotEqual(None, protocolinfo_response.tor_version)
    self.assertNotEqual(None, protocolinfo_response.auth_methods)

    self.assert_matches_test_config(protocolinfo_response)

  @require_controller
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_protocolinfo_path_expansion(self):
    """
    If we're running with the 'RELATIVE' target then test_parsing() will
    exercise cookie path expansion when we're able to query the pid by our
    prcess name. This test selectively disables system.call() so we exercise
    the expansion via our control port or socket file.

    This test is largely redundant with test_parsing() if we aren't running
    with the 'RELATIVE' target.
    """

    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      lookup_prefixes = (
        stem.util.system.GET_PID_BY_PORT_NETSTAT,
        stem.util.system.GET_PID_BY_PORT_SOCKSTAT % '',
        stem.util.system.GET_PID_BY_PORT_LSOF,
        stem.util.system.GET_CWD_PWDX % '',
        'lsof -a -p ')

      control_socket = stem.socket.ControlPort(port = test.runner.CONTROL_PORT)
    else:
      lookup_prefixes = (
        stem.util.system.GET_PID_BY_FILE_LSOF % '',
        stem.util.system.GET_CWD_PWDX % '',
        'lsof -a -p ')

      control_socket = stem.socket.ControlSocketFile(test.runner.CONTROL_SOCKET_PATH)

    call_replacement = filter_system_call(lookup_prefixes)

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
      self.assert_matches_test_config(protocolinfo_response)

      # we should have a usable socket at this point
      self.assertTrue(control_socket.is_alive())
      control_socket.close()

  @require_controller
  def test_multiple_protocolinfo_calls(self):
    """
    Tests making repeated PROTOCOLINFO queries. This use case is interesting
    because tor will shut down the socket and stem should transparently
    re-establish it.
    """

    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      for _ in range(5):
        protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
        self.assert_matches_test_config(protocolinfo_response)

  @require_controller
  def test_pre_disconnected_query(self):
    """
    Tests making a PROTOCOLINFO query when previous use of the socket had
    already disconnected it.
    """

    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      # makes a couple protocolinfo queries outside of get_protocolinfo first
      control_socket.send('PROTOCOLINFO 1')
      control_socket.recv()

      control_socket.send('PROTOCOLINFO 1')
      control_socket.recv()

      protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
      self.assert_matches_test_config(protocolinfo_response)

  def assert_matches_test_config(self, protocolinfo_response):
    """
    Makes assertions that the protocolinfo response's attributes match those of
    the test configuration.
    """

    runner = test.runner.get_runner()
    tor_options = runner.get_options()
    tor_version = runner.get_tor_version()
    auth_methods, auth_cookie_path = [], None

    if test.runner.Torrc.COOKIE in tor_options:
      auth_methods.append(stem.response.protocolinfo.AuthMethod.COOKIE)

      if tor_version >= stem.version.Requirement.AUTH_SAFECOOKIE:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.SAFECOOKIE)

      chroot_path = runner.get_chroot()
      auth_cookie_path = runner.get_auth_cookie_path()

      if chroot_path and auth_cookie_path.startswith(chroot_path):
        auth_cookie_path = auth_cookie_path[len(chroot_path):]

    if test.runner.Torrc.PASSWORD in tor_options:
      auth_methods.append(stem.response.protocolinfo.AuthMethod.PASSWORD)

    if not auth_methods:
      auth_methods.append(stem.response.protocolinfo.AuthMethod.NONE)

    self.assertEqual((), protocolinfo_response.unknown_auth_methods)
    self.assertEqual(tuple(auth_methods), protocolinfo_response.auth_methods)
    self.assertEqual(auth_cookie_path, protocolinfo_response.cookie_path)
