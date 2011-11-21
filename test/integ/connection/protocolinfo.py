"""
Integration tests for the stem.connections.ProtocolInfoResponse class and
related functions.
"""

import unittest

import test.runner
import stem.types
import stem.connection

class TestProtocolInfo(unittest.TestCase):
  """
  Queries and parses PROTOCOLINFO. This should be run with the 'CONNECTION'
  integ target to exercise the widest range of use cases.
  """
  
  def test_parsing(self):
    """
    Makes a PROTOCOLINFO query and processes the response for our control
    connection.
    """
    
    runner = test.runner.get_runner()
    connection_type = runner.get_connection_type()
    
    if connection_type == test.runner.TorConnection.NONE:
      self.skipTest("(no connection)")
    
    control_socket = runner.get_tor_socket(False)
    control_socket_file = control_socket.makefile()
    
    control_socket_file.write("PROTOCOLINFO 1\r\n")
    control_socket_file.flush()
    
    protocolinfo_response = stem.types.read_message(control_socket_file)
    stem.connection.ProtocolInfoResponse.convert(protocolinfo_response)
    
    # according to the control spec the following _could_ differ or be
    # undefined but if that actually happens then it's gonna make people sad
    
    self.assertEqual(1, protocolinfo_response.protocol_version)
    self.assertNotEqual(None, protocolinfo_response.tor_version)
    self.assertNotEqual(None, protocolinfo_response.auth_methods)
    
    self.assertEqual(None, protocolinfo_response.socket)
    self.assert_protocolinfo_attr(protocolinfo_response, connection_type)
  
  def test_get_protocolinfo_port(self):
    """
    Exercises the stem.connection.get_protocolinfo_port function.
    """
    
    connection_type = test.runner.get_runner().get_connection_type()
    
    if test.runner.OPT_PORT in test.runner.CONNECTION_OPTS[connection_type]:
      protocolinfo_response = stem.connection.get_protocolinfo_port(control_port = test.runner.CONTROL_PORT)
      self.assertEqual(None, protocolinfo_response.socket)
      self.assert_protocolinfo_attr(protocolinfo_response, connection_type)
    else:
      # we don't have a control port
      self.assertRaises(stem.types.SocketError, stem.connection.get_protocolinfo_port, "127.0.0.1", test.runner.CONTROL_PORT)
  
  def assert_protocolinfo_attr(self, protocolinfo_response, connection_type):
    """
    Makes assertions that the protocolinfo response's attributes match those of
    a given connection type.
    """
    
    # This should never have test.runner.TorConnection.NONE. If we somehow got
    # a protocolinfo_response from that config then we have an issue. :)
    
    if connection_type == test.runner.TorConnection.NO_AUTH:
      auth_methods = (stem.connection.AuthMethod.NONE,)
    elif connection_type == test.runner.TorConnection.PASSWORD:
      auth_methods = (stem.connection.AuthMethod.PASSWORD,)
    elif connection_type == test.runner.TorConnection.COOKIE:
      auth_methods = (stem.connection.AuthMethod.COOKIE,)
    elif connection_type == test.runner.TorConnection.MULTIPLE:
      auth_methods = (stem.connection.AuthMethod.COOKIE, stem.connection.AuthMethod.PASSWORD)
    elif connection_type == test.runner.TorConnection.SOCKET:
      auth_methods = (stem.connection.AuthMethod.NONE,)
    else:
      self.fail("Unrecognized connection type: %s" % connection_type)
    
    self.assertEqual((), protocolinfo_response.unknown_auth_methods)
    self.assertEqual(auth_methods, protocolinfo_response.auth_methods)
    
    if test.runner.OPT_COOKIE in test.runner.CONNECTION_OPTS[connection_type]:
      auth_cookie_path = test.runner.get_runner().get_auth_cookie_path()
      self.assertEqual(auth_cookie_path, protocolinfo_response.cookie_file)
    else:
      self.assertEqual(None, protocolinfo_response.cookie_file)

