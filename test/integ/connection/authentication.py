"""
Integration tests for authenticating to the control socket via
stem.connection.authenticate_* functions.
"""

import unittest

import test.runner
import stem.connection

# Responses given by tor for various authentication failures. These may change
# in the future and if they do then this test should be updated.

COOKIE_AUTH_FAIL = "Authentication failed: Wrong length on authentication cookie."
PASSWORD_AUTH_FAIL = "Authentication failed: Password did not match HashedControlPassword value from configuration. Maybe you tried a plain text password? If so, the standard requires that you put it in double quotes."
MULTIPLE_AUTH_FAIL = "Authentication failed: Password did not match HashedControlPassword *or* authentication cookie."

class TestAuthenticate(unittest.TestCase):
  """
  Tests the authentication methods. This should be run with the 'CONN_ALL'
  integ target to exercise the widest range of use cases.
  """
  
  def test_authenticate_none(self):
    """
    Tests the authenticate_none function.
    """
    
    runner = test.runner.get_runner()
    connection_type = runner.get_connection_type()
    
    if connection_type == test.runner.TorConnection.NONE:
      self.skipTest("(no connection)")
    
    # If the connection has authentication then this will fail with a message
    # based on the authentication type. If not then this will succeed.
    
    control_socket = test.runner.get_runner().get_tor_socket(False)
    
    connection_options = test.runner.CONNECTION_OPTS[connection_type]
    cookie_auth = test.runner.OPT_COOKIE in connection_options
    password_auth = test.runner.OPT_PASSWORD in connection_options
    
    if cookie_auth or password_auth:
      if cookie_auth and password_auth: failure_msg = MULTIPLE_AUTH_FAIL
      elif cookie_auth: failure_msg = COOKIE_AUTH_FAIL
      else: failure_msg = PASSWORD_AUTH_FAIL
      
      try:
        stem.connection.authenticate_none(control_socket)
        self.fail()
      except ValueError, exc:
        self.assertEqual(failure_msg, str(exc))
    else:
      stem.connection.authenticate_none(control_socket)
      
      # issues a 'GETINFO config-file' query to confirm that we can use the socket
      
      control_socket.send("GETINFO config-file")
      config_file_response = control_socket.recv()
      self.assertEquals("config-file=%s\nOK" % runner.get_torrc_path(), str(config_file_response))

