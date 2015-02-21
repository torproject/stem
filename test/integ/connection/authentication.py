"""
Integration tests for authenticating to the control socket via
stem.connection.authenticate* functions.
"""

import os
import unittest

import stem.connection
import stem.socket
import stem.version
import test.runner

from test.runner import require_controller

# Responses given by tor for various authentication failures. These may change
# in the future and if they do then this test should be updated.

COOKIE_AUTH_FAIL = 'Authentication failed: Wrong length on authentication cookie.'
SAFECOOKIE_AUTH_FAIL = 'Authentication failed: Wrong length for safe cookie response.'
PASSWORD_AUTH_FAIL = 'Authentication failed: Password did not match HashedControlPassword value from configuration. Maybe you tried a plain text password? If so, the standard requires that you put it in double quotes.'
MULTIPLE_AUTH_FAIL = 'Authentication failed: Password did not match HashedControlPassword *or* authentication cookie.'
SAFECOOKIE_AUTHCHALLENGE_FAIL = 'Cookie authentication is disabled'

# this only arises in cookie-only or password-only auth when we authenticate
# with the wrong value
INCORRECT_COOKIE_FAIL = 'Authentication failed: Authentication cookie did not match expected value.'
INCORRECT_SAFECOOKIE_FAIL = 'Authentication failed: Safe cookie response did not match expected value.'
INCORRECT_PASSWORD_FAIL = 'Authentication failed: Password did not match HashedControlPassword value from configuration'


def _can_authenticate(auth_type):
  """
  Checks if a given authentication method can authenticate to our control
  socket.

  :param stem.connection.AuthMethod auth_type: authentication method to check

  :returns: bool that's True if we should be able to authenticate and False otherwise
  """

  runner = test.runner.get_runner()
  tor_options = runner.get_options()
  password_auth = test.runner.Torrc.PASSWORD in tor_options
  cookie_auth = test.runner.Torrc.COOKIE in tor_options
  safecookie_auth = cookie_auth and runner.get_tor_version() >= stem.version.Requirement.AUTH_SAFECOOKIE

  if not password_auth and not cookie_auth:
    # open socket, anything but safecookie will work
    return auth_type != stem.connection.AuthMethod.SAFECOOKIE
  elif auth_type == stem.connection.AuthMethod.PASSWORD:
    return password_auth
  elif auth_type == stem.connection.AuthMethod.COOKIE:
    return cookie_auth
  elif auth_type == stem.connection.AuthMethod.SAFECOOKIE:
    return safecookie_auth
  else:
    return False


def _get_auth_failure_message(auth_type):
  """
  Provides the message that tor will respond with if our current method of
  authentication fails. Note that this test will need to be updated if tor
  changes its rejection reponse.

  :param stem.connection.AuthMethod auth_type: authentication method to check

  :returns: string with the rejection message that tor would provide
  """

  tor_options = test.runner.get_runner().get_options()
  password_auth = test.runner.Torrc.PASSWORD in tor_options
  cookie_auth = test.runner.Torrc.COOKIE in tor_options

  if cookie_auth and password_auth:
    return MULTIPLE_AUTH_FAIL
  elif cookie_auth:
    if auth_type == stem.connection.AuthMethod.COOKIE:
      return INCORRECT_COOKIE_FAIL
    elif auth_type == stem.connection.AuthMethod.SAFECOOKIE:
      return INCORRECT_SAFECOOKIE_FAIL
    else:
      return COOKIE_AUTH_FAIL
  elif password_auth:
    if auth_type == stem.connection.AuthMethod.PASSWORD:
      return INCORRECT_PASSWORD_FAIL
    else:
      return PASSWORD_AUTH_FAIL
  else:
    # The only way that we should fail to authenticate to an open control
    # socket is if we attempt via safecookie (since we get an 'unsupported'
    # response via the AUTHCHALLENGE call rather than AUTHENTICATE). For
    # anything else if we get here it indicates that this test has a bug.

    if auth_type == stem.connection.AuthMethod.SAFECOOKIE:
      return SAFECOOKIE_AUTHCHALLENGE_FAIL

    raise ValueError("No methods of authentication. If this is an open socket then auth shouldn't fail.")


class TestAuthenticate(unittest.TestCase):
  def setUp(self):
    self.cookie_auth_methods = [stem.connection.AuthMethod.COOKIE]

    tor_version = test.runner.get_runner().get_tor_version()
    if tor_version >= stem.version.Requirement.AUTH_SAFECOOKIE:
      self.cookie_auth_methods.append(stem.connection.AuthMethod.SAFECOOKIE)

  @require_controller
  def test_authenticate_general_socket(self):
    """
    Tests that the authenticate function can authenticate to our socket.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_socket(False) as control_socket:
      stem.connection.authenticate(control_socket, test.runner.CONTROL_PASSWORD, runner.get_chroot())
      test.runner.exercise_controller(self, control_socket)

  @require_controller
  def test_authenticate_general_controller(self):
    """
    Tests that the authenticate function can authenticate via a Controller.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller(False) as controller:
      stem.connection.authenticate(controller, test.runner.CONTROL_PASSWORD, runner.get_chroot())
      test.runner.exercise_controller(self, controller)

  @require_controller
  def test_authenticate_general_example(self):
    """
    Tests the authenticate function with something like its pydoc example.
    """

    runner = test.runner.get_runner()
    tor_options = runner.get_options()

    try:
      control_socket = stem.socket.ControlPort(port = test.runner.CONTROL_PORT)
    except stem.SocketError:
      # assert that we didn't have a socket to connect to
      self.assertFalse(test.runner.Torrc.PORT in tor_options)
      return

    try:
      # this authenticate call should work for everything but password-only auth
      stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())
      test.runner.exercise_controller(self, control_socket)
    except stem.connection.IncorrectSocketType:
      self.fail()
    except stem.connection.MissingPassword:
      self.assertTrue(test.runner.Torrc.PASSWORD in tor_options)
      controller_password = test.runner.CONTROL_PASSWORD

      try:
        stem.connection.authenticate_password(control_socket, controller_password)
        test.runner.exercise_controller(self, control_socket)
      except stem.connection.PasswordAuthFailed:
        self.fail()
    except stem.connection.AuthenticationFailure:
      self.fail()
    finally:
      control_socket.close()

  @require_controller
  def test_authenticate_general_password(self):
    """
    Tests the authenticate function's password argument.
    """

    # this is a much better test if we're just using password auth, since
    # authenticate will work reguardless if there's something else to
    # authenticate with

    runner = test.runner.get_runner()
    tor_options = runner.get_options()
    is_password_only = test.runner.Torrc.PASSWORD in tor_options and test.runner.Torrc.COOKIE not in tor_options

    # tests without a password
    with runner.get_tor_socket(False) as control_socket:
      if is_password_only:
        self.assertRaises(stem.connection.MissingPassword, stem.connection.authenticate, control_socket)
      else:
        stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot())
        test.runner.exercise_controller(self, control_socket)

    # tests with the incorrect password
    with runner.get_tor_socket(False) as control_socket:
      if is_password_only:
        self.assertRaises(stem.connection.IncorrectPassword, stem.connection.authenticate, control_socket, 'blarg')
      else:
        stem.connection.authenticate(control_socket, 'blarg', runner.get_chroot())
        test.runner.exercise_controller(self, control_socket)

    # tests with the right password
    with runner.get_tor_socket(False) as control_socket:
      stem.connection.authenticate(control_socket, test.runner.CONTROL_PASSWORD, runner.get_chroot())
      test.runner.exercise_controller(self, control_socket)

  @require_controller
  def test_authenticate_general_cookie(self):
    """
    Tests the authenticate function with only cookie authentication methods.
    This manipulates our PROTOCOLINFO response to test each method
    individually.
    """

    runner = test.runner.get_runner()
    tor_options = runner.get_options()
    is_cookie_only = test.runner.Torrc.COOKIE in tor_options and test.runner.Torrc.PASSWORD not in tor_options

    # test both cookie authentication mechanisms
    with runner.get_tor_socket(False) as control_socket:
      if is_cookie_only:
        for method in (stem.connection.AuthMethod.COOKIE, stem.connection.AuthMethod.SAFECOOKIE):
          protocolinfo_response = stem.connection.get_protocolinfo(control_socket)

          if method in protocolinfo_response.auth_methods:
            # narrow to *only* use cookie auth or safecooke, so we exercise
            # both independently

            protocolinfo_response.auth_methods = (method, )
            stem.connection.authenticate(control_socket, chroot_path = runner.get_chroot(), protocolinfo_response = protocolinfo_response)

  @require_controller
  def test_authenticate_none(self):
    """
    Tests the authenticate_none function.
    """

    auth_type = stem.connection.AuthMethod.NONE

    if _can_authenticate(auth_type):
      self._check_auth(auth_type)
    else:
      self.assertRaises(stem.connection.OpenAuthRejected, self._check_auth, auth_type)

  @require_controller
  def test_authenticate_password(self):
    """
    Tests the authenticate_password function.
    """

    auth_type = stem.connection.AuthMethod.PASSWORD
    auth_value = test.runner.CONTROL_PASSWORD

    if _can_authenticate(auth_type):
      self._check_auth(auth_type, auth_value)
    else:
      self.assertRaises(stem.connection.PasswordAuthRejected, self._check_auth, auth_type, auth_value)

    # Check with an empty, invalid, and quoted password. These should work if
    # we have no authentication, and fail otherwise.

    for auth_value in ('', 'blarg', 'this has a " in it'):
      if _can_authenticate(stem.connection.AuthMethod.NONE):
        self._check_auth(auth_type, auth_value)
      else:
        if _can_authenticate(stem.connection.AuthMethod.PASSWORD):
          exc_type = stem.connection.IncorrectPassword
        else:
          exc_type = stem.connection.PasswordAuthRejected

        self.assertRaises(exc_type, self._check_auth, auth_type, auth_value)

  @require_controller
  def test_authenticate_cookie(self):
    """
    Tests the authenticate_cookie function.
    """

    auth_value = test.runner.get_runner().get_auth_cookie_path()

    for auth_type in self.cookie_auth_methods:
      if not os.path.exists(auth_value):
        # If the authentication cookie doesn't exist then we'll be getting an
        # error for that rather than rejection. This will even fail if
        # _can_authenticate is true because we *can* authenticate with cookie
        # auth but the function will short circuit with failure due to the
        # missing file.

        self.assertRaises(stem.connection.UnreadableCookieFile, self._check_auth, auth_type, auth_value, False)
      elif _can_authenticate(auth_type):
        self._check_auth(auth_type, auth_value)
      else:
        self.assertRaises(stem.connection.CookieAuthRejected, self._check_auth, auth_type, auth_value, False)

  @require_controller
  def test_authenticate_cookie_invalid(self):
    """
    Tests the authenticate_cookie function with a properly sized but incorrect
    value.
    """

    auth_value = test.runner.get_runner().get_test_dir('fake_cookie')

    # we need to create a 32 byte cookie file to load from
    fake_cookie = open(auth_value, 'w')
    fake_cookie.write('0' * 32)
    fake_cookie.close()

    for auth_type in self.cookie_auth_methods:
      if _can_authenticate(stem.connection.AuthMethod.NONE):
        # authentication will work anyway unless this is safecookie
        if auth_type == stem.connection.AuthMethod.COOKIE:
          self._check_auth(auth_type, auth_value)
        elif auth_type == stem.connection.AuthMethod.SAFECOOKIE:
          exc_type = stem.connection.CookieAuthRejected
          self.assertRaises(exc_type, self._check_auth, auth_type, auth_value)
      else:
        if auth_type == stem.connection.AuthMethod.SAFECOOKIE:
          if _can_authenticate(auth_type):
            exc_type = stem.connection.AuthSecurityFailure
          else:
            exc_type = stem.connection.CookieAuthRejected
        elif _can_authenticate(auth_type):
          exc_type = stem.connection.IncorrectCookieValue
        else:
          exc_type = stem.connection.CookieAuthRejected

        self.assertRaises(exc_type, self._check_auth, auth_type, auth_value, False)

    os.remove(auth_value)

  @require_controller
  def test_authenticate_cookie_missing(self):
    """
    Tests the authenticate_cookie function with a path that really, really
    shouldn't exist.
    """

    for auth_type in self.cookie_auth_methods:
      auth_value = "/if/this/exists/then/they're/asking/for/a/failure"
      self.assertRaises(stem.connection.UnreadableCookieFile, self._check_auth, auth_type, auth_value, False)

  @require_controller
  def test_authenticate_cookie_wrong_size(self):
    """
    Tests the authenticate_cookie function with our torrc as an auth cookie.
    This is to confirm that we won't read arbitrary files to the control
    socket.
    """

    auth_value = test.runner.get_runner().get_torrc_path(True)

    for auth_type in self.cookie_auth_methods:
      if os.path.getsize(auth_value) == 32:
        # Weird coincidence? Fail so we can pick another file to check against.
        self.fail('Our torrc is 32 bytes, preventing the test_authenticate_cookie_wrong_size test from running.')
      else:
        self.assertRaises(stem.connection.IncorrectCookieSize, self._check_auth, auth_type, auth_value, False)

  def _check_auth(self, auth_type, auth_arg = None, check_message = True):
    """
    Attempts to use the given type of authentication against tor's control
    socket. If it succeeds then we check that the socket can then be used. If
    not then we check that this gives a message that we'd expect then raises
    the exception.

    :param stem.connection.AuthMethod auth_type: method by which we should authentiate to the control socket
    :param str auth_arg: argument to be passed to the authentication function
    :param bool check_message: checks that failure messages are what we'd expect

    :raises: :class:`stem.connection.AuthenticationFailure` if the authentication fails
    """

    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      # run the authentication, re-raising if there's a problem
      try:
        if auth_type == stem.connection.AuthMethod.NONE:
          stem.connection.authenticate_none(control_socket)
        elif auth_type == stem.connection.AuthMethod.PASSWORD:
          stem.connection.authenticate_password(control_socket, auth_arg)
        elif auth_type == stem.connection.AuthMethod.COOKIE:
          stem.connection.authenticate_cookie(control_socket, auth_arg)
        elif auth_type == stem.connection.AuthMethod.SAFECOOKIE:
          stem.connection.authenticate_safecookie(control_socket, auth_arg)

        test.runner.exercise_controller(self, control_socket)
      except stem.connection.AuthenticationFailure as exc:
        # authentication functions should re-attach on failure
        self.assertTrue(control_socket.is_alive())

        # check that we got the failure message that we'd expect
        if check_message:
          failure_msg = _get_auth_failure_message(auth_type)
          self.assertEqual(failure_msg, str(exc))

        raise exc
