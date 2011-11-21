"""
Integration tests for the stem.connections.ProtocolInfoResponse class.
"""

import socket
import unittest

import test.runner
import stem.types
import stem.connection

class TestProtocolInfoResponse(unittest.TestCase):
  """
  Processes a ProtocolInfo query for a variety of setups.
  """
  
  def testProtocolInfoResponse(self):
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
    
    control_socket_file.write("PROTOCOLINFO\r\n")
    control_socket_file.flush()
    
    protocolinfo_response = stem.types.read_message(control_socket_file)
    stem.connection.ProtocolInfoResponse.convert(protocolinfo_response)
    
    # according to the control spec the following _could_ differ or be
    # undefined but if that actually happens then it's gonna make people sad
    
    self.assertEqual(1, protocolinfo_response.protocol_version)
    self.assertNotEqual(None, protocolinfo_response.tor_version)
    self.assertNotEqual(None, protocolinfo_response.auth_methods)
    
    self.assertEqual((), protocolinfo_response.unknown_auth_methods)
    self.assertEqual(None, protocolinfo_response.socket)
    
    if connection_type == test.runner.TorConnection.NO_AUTH:
      self.assertEqual((stem.connection.AuthMethod.NONE,), protocolinfo_response.auth_methods)
      self.assertEqual(None, protocolinfo_response.cookie_file)
    elif connection_type == test.runner.TorConnection.PASSWORD:
      self.assertEqual((stem.connection.AuthMethod.PASSWORD,), protocolinfo_response.auth_methods)
      self.assertEqual(None, protocolinfo_response.cookie_file)
    elif connection_type == test.runner.TorConnection.COOKIE:
      self.assertEqual((stem.connection.AuthMethod.COOKIE,), protocolinfo_response.auth_methods)
      self.assertEqual(runner.get_auth_cookie_path(), protocolinfo_response.cookie_file)
    elif connection_type == test.runner.TorConnection.MULTIPLE:
      self.assertEqual((stem.connection.AuthMethod.COOKIE, stem.connection.AuthMethod.PASSWORD), protocolinfo_response.auth_methods)
      self.assertEqual(runner.get_auth_cookie_path(), protocolinfo_response.cookie_file)
    elif connection_type == test.runner.TorConnection.SOCKET:
      self.assertEqual((stem.connection.AuthMethod.NONE,), protocolinfo_response.auth_methods)
      self.assertEqual(None, protocolinfo_response.cookie_file)
    else:
      self.fail("Unrecognized connection type: %s" % connection_type)

