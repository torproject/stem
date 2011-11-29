"""
Integration tests for authenticating to the control socket via
stem.connection.authenticate_* functions.
"""

import unittest
import functools

import test.runner
import stem.connection

# Responses given by tor for various authentication failures. These may change
# in the future and if they do then this test should be updated.

COOKIE_AUTH_FAIL = "Authentication failed: Wrong length on authentication cookie."
PASSWORD_AUTH_FAIL = "Authentication failed: Password did not match HashedControlPassword value from configuration. Maybe you tried a plain text password? If so, the standard requires that you put it in double quotes."
MULTIPLE_AUTH_FAIL = "Authentication failed: Password did not match HashedControlPassword *or* authentication cookie."

# this only arises in password-only auth when we authenticate by password
INCORRECT_PASSWORD_FAIL = "Authentication failed: Password did not match HashedControlPassword value from configuration"

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
    
    expect_success = self._is_authenticateable(stem.connection.AuthMethod.NONE)
    self._check_auth(stem.connection.AuthMethod.NONE, None, expect_success)
  
  def test_authenticate_password(self):
    """
    Tests the authenticate_password function.
    """
    
    runner = test.runner.get_runner()
    connection_type = runner.get_connection_type()
    
    if connection_type == test.runner.TorConnection.NONE:
      self.skipTest("(no connection)")
    
    expect_success = self._is_authenticateable(stem.connection.AuthMethod.PASSWORD)
    self._check_auth(stem.connection.AuthMethod.PASSWORD, test.runner.CONTROL_PASSWORD, expect_success)
    
    # Check with an empty, invalid, and quoted password. These should work if
    # we have no authentication, and fail otherwise.
    
    expect_success = self._is_authenticateable(stem.connection.AuthMethod.NONE)
    self._check_auth(stem.connection.AuthMethod.PASSWORD, "", expect_success)
    self._check_auth(stem.connection.AuthMethod.PASSWORD, "blarg", expect_success)
    self._check_auth(stem.connection.AuthMethod.PASSWORD, "this has a \" in it", expect_success)
  
  def _get_socket_auth(self):
    """
    Provides the types of authentication that our current test socket accepts.
    
    Returns:
      bool tuple of the form (password_auth, cookie_auth)
    """
    
    connection_type = test.runner.get_runner().get_connection_type()
    connection_options = test.runner.CONNECTION_OPTS[connection_type]
    password_auth = test.runner.OPT_PASSWORD in connection_options
    cookie_auth = test.runner.OPT_COOKIE in connection_options
    
    return password_auth, cookie_auth
  
  def _is_authenticateable(self, auth_type):
    """
    Checks if the given authentication type should be able to authenticate to
    our current socket.
    
    Arguments:
      auth_type (stem.connection.AuthMethod) - authentication method to check
    
    Returns:
      bool that's True if we should be able to authenticate and False otherwise
    """
    
    password_auth, cookie_auth = self._get_socket_auth()
    
    # If the control socket is open then all authentication methods will be
    # accepted. Otherwise check if our auth type matches what the socket
    # accepts.
    
    if not password_auth and not cookie_auth: return True
    elif auth_type == stem.connection.AuthMethod.PASSWORD: return password_auth
    elif auth_type == stem.connection.AuthMethod.COOKIE: return cookie_auth
    else: return False
  
  def _check_auth(self, auth_type, auth_value, expect_success):
    """
    Attempts to use the given authentication function against our connection.
    If this works then checks that we can use the connection. If not then we
    check that the error message is what we'd expect.
    
    Arguments:
      auth_type (stem.connection.AuthMethod) - method by which we should
          authentiate to the control socket
      auth_value (str) - value to be provided to the authentication function
      expect_success (bool) - true if the authentication should succeed, false
          otherwise
    """
    
    runner = test.runner.get_runner()
    control_socket = runner.get_tor_socket(False)
    password_auth, cookie_auth = self._get_socket_auth()
    
    # construct the function call
    
    if auth_type == stem.connection.AuthMethod.NONE:
      auth_function = stem.connection.authenticate_none
    elif auth_type == stem.connection.AuthMethod.PASSWORD:
      auth_function = stem.connection.authenticate_password
    elif auth_type == stem.connection.AuthMethod.COOKIE:
      auth_function = None # TODO: fill in
    else:
      raise ValueError("unexpected auth type: %s" % auth_type)
    
    if auth_value != None:
      auth_function = functools.partial(auth_function, control_socket, auth_value)
    else:
      auth_function = functools.partial(auth_function, control_socket)
    
    if expect_success:
      auth_function()
      
      # issues a 'GETINFO config-file' query to confirm that we can use the socket
      
      control_socket.send("GETINFO config-file")
      config_file_response = control_socket.recv()
      self.assertEquals("config-file=%s\nOK" % runner.get_torrc_path(), str(config_file_response))
      control_socket.close()
    else:
      if cookie_auth and password_auth: failure_msg = MULTIPLE_AUTH_FAIL
      elif cookie_auth: failure_msg = COOKIE_AUTH_FAIL
      else:
        # if we're attempting to authenticate with a password then it's a
        # truncated message
        
        if auth_type == stem.connection.AuthMethod.PASSWORD:
          failure_msg = INCORRECT_PASSWORD_FAIL
        else:
          failure_msg = PASSWORD_AUTH_FAIL
      
      try:
        auth_function()
        self.fail()
      except ValueError, exc:
        self.assertEqual(failure_msg, str(exc))

