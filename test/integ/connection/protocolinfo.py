"""
Integration tests for the stem.connection.ProtocolInfoResponse class and
related functions.
"""

import unittest

import test.runner
import stem.socket
import stem.connection
import stem.util.system

class TestProtocolInfo(unittest.TestCase):
  def tearDown(self):
    # resets call mocking back to being disabled
    stem.util.system.CALL_MOCKING = None
  
  def test_parsing(self):
    """
    Makes a PROTOCOLINFO query and processes the response for our control
    connection.
    """
    
    runner = test.runner.get_runner()
    
    if not runner.is_accessible():
      self.skipTest("(no connection)")
    
    control_socket = runner.get_tor_socket(False)
    
    control_socket.send("PROTOCOLINFO 1")
    protocolinfo_response = control_socket.recv()
    stem.connection.ProtocolInfoResponse.convert(protocolinfo_response)
    control_socket.close()
    
    # according to the control spec the following _could_ differ or be
    # undefined but if that actually happens then it's gonna make people sad
    
    self.assertEqual(1, protocolinfo_response.protocol_version)
    self.assertNotEqual(None, protocolinfo_response.tor_version)
    self.assertNotEqual(None, protocolinfo_response.auth_methods)
    
    self.assert_protocolinfo_attr(protocolinfo_response)
  
  def test_get_protocolinfo_by_port(self):
    """
    Exercises the stem.connection.get_protocolinfo function with a control
    port.
    """
    
    # If we have both the 'RELATIVE' target and a cookie then test_parsing
    # should exercise cookie expansion using a pid lookup by process name.
    # Disabling those lookups so we exercise the lookup by port/socket file
    # too. Gotta remember the get_cwd functions too.
    
    cwd_by_port_lookup_prefixes = (
      stem.util.system.GET_PID_BY_PORT_NETSTAT,
      stem.util.system.GET_PID_BY_PORT_SOCKSTAT % "",
      stem.util.system.GET_PID_BY_PORT_LSOF,
      stem.util.system.GET_CWD_PWDX % "",
      "lsof -a -p ")
    
    def port_lookup_filter(command):
      for prefix in cwd_by_port_lookup_prefixes:
        if command.startswith(prefix): return True
      
      return False
    
    stem.util.system.CALL_MOCKING = port_lookup_filter
    
    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      control_socket = stem.socket.ControlPort(control_port = test.runner.CONTROL_PORT)
      protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
      self.assert_protocolinfo_attr(protocolinfo_response)
      
      # we should have a usable socket at this point
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
    else:
      # we don't have a control port
      self.assertRaises(stem.socket.SocketError, stem.socket.ControlPort, "127.0.0.1", test.runner.CONTROL_PORT)
  
  def test_get_protocolinfo_by_socket(self):
    """
    Exercises the stem.connection.get_protocolinfo function with a control
    socket.
    """
    
    cwd_by_socket_lookup_prefixes = (
      stem.util.system.GET_PID_BY_FILE_LSOF % "",
      stem.util.system.GET_CWD_PWDX % "",
      "lsof -a -p ")
    
    def socket_lookup_filter(command):
      for prefix in cwd_by_socket_lookup_prefixes:
        if command.startswith(prefix): return True
      
      return False
    
    stem.util.system.CALL_MOCKING = socket_lookup_filter
    
    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      control_socket = stem.socket.ControlSocketFile(test.runner.CONTROL_SOCKET_PATH)
      protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
      self.assert_protocolinfo_attr(protocolinfo_response)
      
      # we should have a usable socket at this point
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
    else:
      # we don't have a control socket
      self.assertRaises(stem.socket.SocketError, stem.socket.ControlSocketFile, test.runner.CONTROL_SOCKET_PATH)
  
  def test_multiple_protocolinfo_calls(self):
    """
    Tests making repeated PROTOCOLINFO queries. This use case is interesting
    because tor will shut down the socket and stem should transparently
    re-establish it.
    """
    
    runner = test.runner.get_runner()
    
    if not runner.is_accessible():
      self.skipTest("(no connection)")
    
    control_socket = runner.get_tor_socket(False)
    
    for i in range(5):
      protocolinfo_response = stem.connection.get_protocolinfo(control_socket)
      self.assert_protocolinfo_attr(protocolinfo_response)
    
    control_socket.close()
  
  def assert_protocolinfo_attr(self, protocolinfo_response):
    """
    Makes assertions that the protocolinfo response's attributes match those of
    a given connection type.
    """
    
    # This should never have test.runner.TorConnection.NONE. If we somehow got
    # a protocolinfo_response from that config then we have an issue. :)
    
    tor_options = test.runner.get_runner().get_options()
    
    auth_methods = []
    
    if test.runner.Torrc.COOKIE in tor_options:
      auth_methods.append(stem.connection.AuthMethod.COOKIE)
    
    if test.runner.Torrc.PASSWORD in tor_options:
      auth_methods.append(stem.connection.AuthMethod.PASSWORD)
    
    if not auth_methods:
      auth_methods.append(stem.connection.AuthMethod.NONE)
    
    self.assertEqual((), protocolinfo_response.unknown_auth_methods)
    self.assertEqual(tuple(auth_methods), protocolinfo_response.auth_methods)
    
    auth_cookie_path = None
    if test.runner.Torrc.COOKIE in tor_options:
      auth_cookie_path = test.runner.get_runner().get_auth_cookie_path()
    
    self.assertEqual(auth_cookie_path, protocolinfo_response.cookie_path)

