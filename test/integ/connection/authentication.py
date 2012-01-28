"""
Integration tests for authenticating to the control socket via
stem.connection.authenticate* functions.
"""

import os
import unittest
import functools

import test.runner
import stem.connection
import stem.socket

# Responses given by tor for various authentication failures. These may change
# in the future and if they do then this test should be updated.

COOKIE_AUTH_FAIL = "Authentication failed: Wrong length on authentication cookie."
PASSWORD_AUTH_FAIL = "Authentication failed: Password did not match HashedControlPassword value from configuration. Maybe you tried a plain text password? If so, the standard requires that you put it in double quotes."
MULTIPLE_AUTH_FAIL = "Authentication failed: Password did not match HashedControlPassword *or* authentication cookie."

# this only arises in cookie-only or password-only auth when we authenticate
# with the wrong value
INCORRECT_COOKIE_FAIL = "Authentication failed: Authentication cookie did not match expected value."
INCORRECT_PASSWORD_FAIL = "Authentication failed: Password did not match HashedControlPassword value from configuration"

class TestAuthenticate(unittest.TestCase):
  def setUp(self):
    # none of these tests apply if there's no control connection
    if not test.runner.get_runner().is_accessible():
      self.skipTest("(no connection)")
  
  def test_authenticate_general(self):
    """
    Tests that the authenticate function can authenticate to our socket.
    """
    
    control_socket = test.runner.get_runner().get_tor_socket(False)
    stem.connection.authenticate(control_socket, test.runner.CONTROL_PASSWORD)
    test.runner.exercise_socket(self, control_socket)
    control_socket.close()
  
  def test_authenticate_general_example(self):
    """
    Tests the authenticate function with something like its pydoc example.
    """
    
    tor_options = test.runner.get_runner().get_options()
    
    try:
      control_socket = stem.socket.ControlPort(control_port = test.runner.CONTROL_PORT)
    except stem.socket.SocketError:
      # assert that we didn't have a socket to connect to
      self.assertFalse(test.runner.Torrc.PORT in tor_options)
      return
    
    try:
      # this authenticate call should work for everything but password-only auth
      stem.connection.authenticate(control_socket)
      test.runner.exercise_socket(self, control_socket)
    except stem.connection.IncorrectSocketType:
      self.fail()
    except stem.connection.MissingPassword:
      self.assertTrue(test.runner.Torrc.PASSWORD in tor_options)
      controller_password = test.runner.CONTROL_PASSWORD
      
      try:
        stem.connection.authenticate_password(control_socket, controller_password)
        test.runner.exercise_socket(self, control_socket)
      except stem.connection.PasswordAuthFailed:
        self.fail()
    except stem.connection.AuthenticationFailure:
      self.fail()
    finally:
      control_socket.close()
  
  def test_authenticate_general_password(self):
    """
    Tests the authenticate function's password argument.
    """
    
    # this is a much better test if we're just using password auth, since
    # authenticate will work reguardless if there's something else to
    # authenticate with
    
    runner = test.runner.get_runner()
    tor_options = runner.get_options()
    is_password_only = test.runner.Torrc.PASSWORD in tor_options and not test.runner.Torrc.COOKIE in tor_options
    
    # tests without a password
    control_socket = runner.get_tor_socket(False)
    auth_function = functools.partial(stem.connection.authenticate, control_socket)
    
    if is_password_only:
      self.assertRaises(stem.connection.MissingPassword, auth_function)
    else:
      auth_function()
      test.runner.exercise_socket(self, control_socket)
    
    control_socket.close()
    
    # tests with the incorrect password
    control_socket = runner.get_tor_socket(False)
    auth_function = functools.partial(stem.connection.authenticate, control_socket, "blarg")
    
    if is_password_only:
      self.assertRaises(stem.connection.IncorrectPassword, auth_function)
    else:
      auth_function()
      test.runner.exercise_socket(self, control_socket)
    
    control_socket.close()
    
    # tests with the right password
    control_socket = runner.get_tor_socket(False)
    stem.connection.authenticate(control_socket, test.runner.CONTROL_PASSWORD)
    test.runner.exercise_socket(self, control_socket)
    control_socket.close()
  
  def test_authenticate_none(self):
    """
    Tests the authenticate_none function.
    """
    
    auth_type = stem.connection.AuthMethod.NONE
    if self._can_authenticate(auth_type):
      self._check_auth(auth_type)
    else:
      self.assertRaises(stem.connection.OpenAuthRejected, self._check_auth, auth_type)
      self._assert_auth_rejected_msg(auth_type)
  
  def test_authenticate_password(self):
    """
    Tests the authenticate_password function.
    """
    
    auth_type = stem.connection.AuthMethod.PASSWORD
    auth_value = test.runner.CONTROL_PASSWORD
    
    if self._can_authenticate(auth_type):
      self._check_auth(auth_type, auth_value)
    else:
      self.assertRaises(stem.connection.PasswordAuthRejected, self._check_auth, auth_type, auth_value)
      self._assert_auth_rejected_msg(auth_type, auth_value)
    
    # Check with an empty, invalid, and quoted password. These should work if
    # we have no authentication, and fail otherwise.
    
    for auth_value in ("", "blarg", "this has a \" in it"):
      if self._can_authenticate(stem.connection.AuthMethod.NONE):
        self._check_auth(auth_type, auth_value)
      else:
        if self._can_authenticate(stem.connection.AuthMethod.PASSWORD):
          exc_type = stem.connection.IncorrectPassword
        else:
          exc_type = stem.connection.PasswordAuthRejected
        
        self.assertRaises(exc_type, self._check_auth, auth_type, auth_value)
        self._assert_auth_rejected_msg(auth_type, auth_value)
  
  def test_authenticate_cookie(self):
    """
    Tests the authenticate_cookie function.
    """
    
    auth_type = stem.connection.AuthMethod.COOKIE
    auth_value = test.runner.get_runner().get_auth_cookie_path()
    
    if not os.path.exists(auth_value):
      # If the authentication cookie doesn't exist then we'll be getting an
      # error for that rather than rejection. This will even fail if
      # _can_authenticate is true because we *can* authenticate with cookie
      # auth but the function will short circuit with failure due to the
      # missing file.
      
      self.assertRaises(stem.connection.UnreadableCookieFile, self._check_auth, auth_type, auth_value)
    elif self._can_authenticate(auth_type):
      self._check_auth(auth_type, auth_value)
    else:
      self.assertRaises(stem.connection.CookieAuthRejected, self._check_auth, auth_type, auth_value)
      self._assert_auth_rejected_msg(auth_type, auth_value)
  
  def test_authenticate_cookie_invalid(self):
    """
    Tests the authenticate_cookie function with a properly sized but incorrect
    value.
    """
    
    auth_type = stem.connection.AuthMethod.COOKIE
    auth_value = os.path.join(test.runner.get_runner().get_test_dir(), "fake_cookie")
    
    # we need to create a 32 byte cookie file to load from
    fake_cookie = open(auth_value, "w")
    fake_cookie.write("0" * 32)
    fake_cookie.close()
    
    if self._can_authenticate(stem.connection.AuthMethod.NONE):
      # authentication will work anyway
      self._check_auth(auth_type, auth_value)
    else:
      if self._can_authenticate(auth_type):
        exc_type = stem.connection.IncorrectCookieValue
      else:
        exc_type = stem.connection.CookieAuthRejected
      
      self.assertRaises(exc_type, self._check_auth, auth_type, auth_value)
      self._assert_auth_rejected_msg(auth_type, auth_value)
    
    os.remove(auth_value)
  
  def test_authenticate_cookie_missing(self):
    """
    Tests the authenticate_cookie function with a path that really, really
    shouldn't exist.
    """
    
    auth_type = stem.connection.AuthMethod.COOKIE
    auth_value = "/if/this/exists/then/they're/asking/for/a/failure"
    self.assertRaises(stem.connection.UnreadableCookieFile, self._check_auth, auth_type, auth_value)
  
  def test_authenticate_cookie_wrong_size(self):
    """
    Tests the authenticate_cookie function with our torrc as an auth cookie.
    This is to confirm that we won't read arbitrary files to the control
    socket.
    """
    
    auth_type = stem.connection.AuthMethod.COOKIE
    auth_value = test.runner.get_runner().get_torrc_path()
    
    if os.path.getsize(auth_value) == 32:
      # Weird coincidence? Fail so we can pick another file to check against.
      self.fail("Our torrc is 32 bytes, preventing the test_authenticate_cookie_wrong_size test from running.")
    else:
      self.assertRaises(stem.connection.IncorrectCookieSize, self._check_auth, auth_type, auth_value)
  
  def _get_socket_auth(self):
    """
    Provides the types of authentication that our current test socket accepts.
    
    Returns:
      bool tuple of the form (password_auth, cookie_auth)
    """
    
    tor_options = test.runner.get_runner().get_options()
    password_auth = test.runner.Torrc.PASSWORD in tor_options
    cookie_auth = test.runner.Torrc.COOKIE in tor_options
    
    return password_auth, cookie_auth
  
  def _can_authenticate(self, auth_type):
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
  
  def _get_auth_function(self, control_socket, auth_type, *auth_args):
    """
    Constructs a functor that performs the given authentication without
    additional arguments.
    
    Arguments:
      control_socket (stem.socket.ControlSocket) - socket for the function to
          authenticate to
      auth_type (stem.connection.AuthMethod) - method by which we should
          authentiate to the control socket
      auth_args (str) - arguments to be passed to the authentication function
    """
    
    if auth_type == stem.connection.AuthMethod.NONE:
      auth_function = stem.connection.authenticate_none
    elif auth_type == stem.connection.AuthMethod.PASSWORD:
      auth_function = stem.connection.authenticate_password
    elif auth_type == stem.connection.AuthMethod.COOKIE:
      auth_function = stem.connection.authenticate_cookie
    else:
      raise ValueError("unexpected auth type: %s" % auth_type)
    
    if auth_args:
      return functools.partial(auth_function, control_socket, *auth_args)
    else:
      return functools.partial(auth_function, control_socket)
  
  def _assert_auth_rejected_msg(self, auth_type, *auth_args):
    """
    This asserts that authentication will fail with the rejection message given
    by tor. Note that this test will need to be updated if tor changes its
    rejection reponse.
    
    Arguments:
      auth_type (stem.connection.AuthMethod) - method by which we should
          authentiate to the control socket
      auth_args (str) - arguments to be passed to the authentication function
    """
    
    control_socket = test.runner.get_runner().get_tor_socket(False)
    auth_function = self._get_auth_function(control_socket, auth_type, *auth_args)
    password_auth, cookie_auth = self._get_socket_auth()
    
    if cookie_auth and password_auth:
      failure_msg = MULTIPLE_AUTH_FAIL
    elif cookie_auth:
      if auth_type == stem.connection.AuthMethod.COOKIE:
        failure_msg = INCORRECT_COOKIE_FAIL
      else:
        failure_msg = COOKIE_AUTH_FAIL
    elif password_auth:
      if auth_type == stem.connection.AuthMethod.PASSWORD:
        failure_msg = INCORRECT_PASSWORD_FAIL
      else:
        failure_msg = PASSWORD_AUTH_FAIL
    else:
      # shouldn't happen, if so then the test has a bug
      raise ValueError("No methods of authentication. If this is an open socket then auth shoulnd't fail.")
    
    try:
      auth_function()
      control_socket.close()
      self.fail()
    except stem.connection.AuthenticationFailure, exc:
      self.assertTrue(control_socket.is_alive())
      self.assertEqual(failure_msg, str(exc))
      control_socket.close()
  
  def _check_auth(self, auth_type, *auth_args):
    """
    Attempts to use the given authentication function against our connection.
    If this works then checks that we can use the connection. If not then this
    raises the exception.
    
    Arguments:
      auth_type (stem.connection.AuthMethod) - method by which we should
          authentiate to the control socket
      auth_args (str) - arguments to be passed to the authentication function
    
    Raises:
      stem.connection.AuthenticationFailure if the authentication fails
    """
    
    control_socket = test.runner.get_runner().get_tor_socket(False)
    auth_function = self._get_auth_function(control_socket, auth_type, *auth_args)
    
    # run the authentication, re-raising if there's a problem
    try:
      auth_function()
    except stem.connection.AuthenticationFailure, exc:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      raise exc
    
    test.runner.exercise_socket(self, control_socket)
    control_socket.close()

