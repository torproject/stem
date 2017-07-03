"""
Unit tests for the stem.response.protocolinfo.ProtocolInfoResponse class.
"""

import unittest

import stem.response
import stem.response.protocolinfo
import stem.socket
import stem.util.proc
import stem.util.system
import stem.version

from stem.response import ControlMessage
from stem.response.protocolinfo import AuthMethod

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

NO_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=NULL
250-VERSION Tor="0.2.1.30"
250 OK"""

PASSWORD_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=HASHEDPASSWORD
250-VERSION Tor="0.2.1.30"
250 OK"""

COOKIE_AUTH = r"""250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE COOKIEFILE="/tmp/my data\\\"dir//control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK"""

MULTIPLE_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE,HASHEDPASSWORD COOKIEFILE="/home/atagar/.tor/control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK"""

UNKNOWN_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=MAGIC,HASHEDPASSWORD,PIXIE_DUST
250-VERSION Tor="0.2.1.30"
250 OK"""

MINIMUM_RESPONSE = """250-PROTOCOLINFO 5
250 OK"""

UNICODE_COOKIE_PATH = r"""250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE COOKIEFILE="/home/user/\346\226\207\346\241\243/tor-browser_en-US/Browser/TorBrowser/Data/Tor/control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK"""

RELATIVE_COOKIE_PATH = r"""250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE COOKIEFILE="./tor-browser_en-US/Data/control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK"""

EXPECTED_UNICODE_PATH = b"/home/user/\346\226\207\346\241\243/tor-browser_en-US/Browser/TorBrowser/Data/Tor/control_auth_cookie".decode('utf-8')


class TestProtocolInfoResponse(unittest.TestCase):
  def test_convert(self):
    """
    Exercises functionality of the convert method both when it works and
    there's an error.
    """

    # working case
    control_message = ControlMessage.from_str(NO_AUTH, 'PROTOCOLINFO', normalize = True)

    # now this should be a ProtocolInfoResponse (ControlMessage subclass)
    self.assertTrue(isinstance(control_message, stem.response.ControlMessage))
    self.assertTrue(isinstance(control_message, stem.response.protocolinfo.ProtocolInfoResponse))

    # exercise some of the ControlMessage functionality
    raw_content = (NO_AUTH + '\n').replace('\n', '\r\n')
    self.assertEqual(raw_content, control_message.raw_content())
    self.assertTrue(str(control_message).startswith('PROTOCOLINFO 1'))

    # attempt to convert the wrong type
    self.assertRaises(TypeError, stem.response.convert, 'PROTOCOLINFO', 'hello world')

    # attempt to convert a different message type
    self.assertRaises(stem.ProtocolError, ControlMessage.from_str, '650 BW 32326 2856\r\n', 'PROTOCOLINFO')

  def test_no_auth(self):
    """
    Checks a response when there's no authentication.
    """

    control_message = ControlMessage.from_str(NO_AUTH, 'PROTOCOLINFO', normalize = True)
    self.assertEqual(1, control_message.protocol_version)
    self.assertEqual(stem.version.Version('0.2.1.30'), control_message.tor_version)
    self.assertEqual((AuthMethod.NONE, ), control_message.auth_methods)
    self.assertEqual((), control_message.unknown_auth_methods)
    self.assertEqual(None, control_message.cookie_path)

  def test_password_auth(self):
    """
    Checks a response with password authentication.
    """

    control_message = ControlMessage.from_str(PASSWORD_AUTH, 'PROTOCOLINFO', normalize = True)
    self.assertEqual((AuthMethod.PASSWORD, ), control_message.auth_methods)

  def test_cookie_auth(self):
    """
    Checks a response with cookie authentication and a path including escape
    characters.
    """

    control_message = ControlMessage.from_str(COOKIE_AUTH, 'PROTOCOLINFO', normalize = True)
    self.assertEqual((AuthMethod.COOKIE, ), control_message.auth_methods)
    self.assertEqual('/tmp/my data\\"dir//control_auth_cookie', control_message.cookie_path)

  def test_multiple_auth(self):
    """
    Checks a response with multiple authentication methods.
    """

    control_message = ControlMessage.from_str(MULTIPLE_AUTH, 'PROTOCOLINFO', normalize = True)
    self.assertEqual((AuthMethod.COOKIE, AuthMethod.PASSWORD), control_message.auth_methods)
    self.assertEqual('/home/atagar/.tor/control_auth_cookie', control_message.cookie_path)

  def test_unknown_auth(self):
    """
    Checks a response with an unrecognized authtentication method.
    """

    control_message = ControlMessage.from_str(UNKNOWN_AUTH, 'PROTOCOLINFO', normalize = True)
    self.assertEqual((AuthMethod.UNKNOWN, AuthMethod.PASSWORD), control_message.auth_methods)
    self.assertEqual(('MAGIC', 'PIXIE_DUST'), control_message.unknown_auth_methods)

  def test_minimum_response(self):
    """
    Checks a PROTOCOLINFO response that only contains the minimum amount of
    information to be a valid response.
    """

    control_message = ControlMessage.from_str(MINIMUM_RESPONSE, 'PROTOCOLINFO', normalize = True)
    self.assertEqual(5, control_message.protocol_version)
    self.assertEqual(None, control_message.tor_version)
    self.assertEqual((), control_message.auth_methods)
    self.assertEqual((), control_message.unknown_auth_methods)
    self.assertEqual(None, control_message.cookie_path)

  @patch('sys.getfilesystemencoding', Mock(return_value = 'UTF-8'))
  def test_unicode_cookie(self):
    """
    Checks an authentication cookie with a unicode path.
    """

    control_message = ControlMessage.from_str(UNICODE_COOKIE_PATH, 'PROTOCOLINFO', normalize = True)
    self.assertEqual(EXPECTED_UNICODE_PATH, control_message.cookie_path)
