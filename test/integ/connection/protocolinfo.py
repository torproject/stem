"""
Integration tests for the stem.connection.ProtocolInfoResponse class and
related functions.
"""

import unittest

import test.runner
import stem.socket
import stem.connection
import stem.util.system
import test.mocking as mocking
from test.integ.util.system import filter_system_call

class TestProtocolInfo(unittest.TestCase):
  def setUp(self):
    test.runner.require_control(self)
    mocking.mock(stem.util.proc.is_available, mocking.return_false())
    mocking.mock(stem.util.system.is_available, mocking.return_true())
  
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_parsing(self):
    """
    Makes a PROTOCOLINFO query and processes the response for our control
    connection.
    """
    
    control_socket = test.runner.get_runner().get_tor_socket(False)
    control_socket.send("PROTOCOLINFO 1")
    protocolinfo_response = control_socket.recv()
    stem.connection.ProtocolInfoResponse.convert(protocolinfo_response)
    control_socket.close()
    
    # according to the control spec the following _could_ differ or be
    # undefined but if that actually happens then it's gonna make people sad
    
    self.assertEqual(1, protocolinfo_response.protocol_version)
    self.assertNotEqual(None, protocolinfo_response.tor_version)
    self.assertNotEqual(None, protocolinfo_response.auth_methods)
    
    self.assert_matches_test_config(protocolinfo_response)
  
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
      cwd_by_port_lookup_prefixes = (
        stem.util.system.GET_PID_BY_PORT_NETSTAT,
        stem.util.system.GET_PID_BY_PORT_SOCKSTAT % "",
        stem.util.system.GET_PID_BY_PORT_LSOF,
        stem.util.system.GET_CWD_PWDX % "",
        "lsof -a -p ")
      
      mocking.mock(stem.util.system.call, filter_system_call(cwd_by_port_lookup_prefixes))
      control_socket = stem.socket.ControlPort(control_port = test.runner.CONTROL_PORT)
    else:
      cwd_by_socket_lookup_prefixes = (
        stem.util.system.GET_PID_BY_FILE_LSOF % "",
        stem.util.system.GET_CWD_PWDX % "",
        "lsof -a -p ")
      
      mocking.mock(stem.util.system.call, filter_system_call(cwd_by_socket_lookup_prefixes))
      control_socket = stem.socket.ControlSocketFile(test.runner.CONTROL_SOCKET_PATH)
    
    protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
    self.assert_matches_test_config(protocolinfo_response)
    
    # we should have a usable socket at this point
    self.assertTrue(control_socket.is_alive())
    control_socket.close()
  
  def test_multiple_protocolinfo_calls(self):
    """
    Tests making repeated PROTOCOLINFO queries. This use case is interesting
    because tor will shut down the socket and stem should transparently
    re-establish it.
    """
    
    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      for i in range(5):
        protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
        self.assert_matches_test_config(protocolinfo_response)
  
  def test_pre_disconnected_query(self):
    """
    Tests making a PROTOCOLINFO query when previous use of the socket had
    already disconnected it.
    """
    
    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      # makes a couple protocolinfo queries outside of get_protocolinfo first
      control_socket.send("PROTOCOLINFO 1")
      control_socket.recv()
      
      control_socket.send("PROTOCOLINFO 1")
      control_socket.recv()
      
      protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
      self.assert_matches_test_config(protocolinfo_response)
  
  def assert_matches_test_config(self, protocolinfo_response):
    """
    Makes assertions that the protocolinfo response's attributes match those of
    the test configuration.
    """
    
    tor_options = test.runner.get_runner().get_options()
    auth_methods, auth_cookie_path = [], None
    
    if test.runner.Torrc.COOKIE in tor_options:
      auth_methods.append(stem.connection.AuthMethod.COOKIE)
      auth_cookie_path = test.runner.get_runner().get_auth_cookie_path()
    
    if test.runner.Torrc.PASSWORD in tor_options:
      auth_methods.append(stem.connection.AuthMethod.PASSWORD)
    
    if not auth_methods:
      auth_methods.append(stem.connection.AuthMethod.NONE)
    
    self.assertEqual((), protocolinfo_response.unknown_auth_methods)
    self.assertEqual(tuple(auth_methods), protocolinfo_response.auth_methods)
    self.assertEqual(auth_cookie_path, protocolinfo_response.cookie_path)

