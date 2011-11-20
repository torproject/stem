"""
Unit tests for the stem.connection.ProtocolInfoResponse class.
"""

import unittest
import StringIO
import stem.connection
import stem.types

NO_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=NULL
250-VERSION Tor="0.2.1.30"
250 OK
""".replace("\n", "\r\n")

PASSWORD_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=HASHEDPASSWORD
250-VERSION Tor="0.2.1.30"
250 OK
""".replace("\n", "\r\n")

COOKIE_AUTH = r"""250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE COOKIEFILE="/tmp/my data\\\"dir//control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK
""".replace("\n", "\r\n")

MULTIPLE_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE,HASHEDPASSWORD COOKIEFILE="/home/atagar/.tor/control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK
""".replace("\n", "\r\n")

UNKNOWN_AUTH = """250-PROTOCOLINFO 1
250-AUTH METHODS=MAGIC,HASHEDPASSWORD,PIXIE_DUST
250-VERSION Tor="0.2.1.30"
250 OK
""".replace("\n", "\r\n")

MINIMUM_RESPONSE = """250-PROTOCOLINFO 5
250 OK
""".replace("\n", "\r\n")

RELATIVE_COOKIE_PATH = r"""250-PROTOCOLINFO 1
250-AUTH METHODS=COOKIE COOKIEFILE="./tor-browser_en-US/Data/control_auth_cookie"
250-VERSION Tor="0.2.1.30"
250 OK
""".replace("\n", "\r\n")

class TestProtocolInfoResponse(unittest.TestCase):
  """
  Tests the parsing of ControlMessages for PROTOCOLINFO responses.
  """
  
  def test_convert(self):
    """
    Exercises functionality of the convert method both when it works and
    there's an error.
    """
    
    # working case
    control_message = stem.types.read_message(StringIO.StringIO(NO_AUTH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    
    # now this should be a ProtocolInfoResponse (ControlMessage subclass)
    self.assertTrue(isinstance(control_message, stem.types.ControlMessage))
    self.assertTrue(isinstance(control_message, stem.connection.ProtocolInfoResponse))
    
    # exercise some of the ControlMessage functionality
    self.assertTrue(str(control_message).startswith("PROTOCOLINFO 1"))
    self.assertEquals(NO_AUTH, control_message.raw_content())
    
    # attempt to convert the wrong type
    self.assertRaises(TypeError, stem.connection.ProtocolInfoResponse.convert, "hello world")
    
    # attempt to convert a different message type
    bw_event_control_message = stem.types.read_message(StringIO.StringIO("650 BW 32326 2856\r\n"))
    self.assertRaises(stem.types.ProtocolError, stem.connection.ProtocolInfoResponse.convert, bw_event_control_message)
  
  def test_no_auth(self):
    """
    Checks a response when there's no authentication.
    """
    
    control_message = stem.types.read_message(StringIO.StringIO(NO_AUTH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    
    self.assertEquals(1, control_message.protocol_version)
    self.assertEquals(stem.types.Version("0.2.1.30"), control_message.tor_version)
    self.assertEquals((stem.connection.AuthMethod.NONE, ), control_message.auth_methods)
    self.assertEquals((), control_message.unknown_auth_methods)
    self.assertEquals(None, control_message.cookie_file)
    self.assertEquals(None, control_message.socket)
  
  def test_password_auth(self):
    """
    Checks a response with password authentication.
    """
    
    control_message = stem.types.read_message(StringIO.StringIO(PASSWORD_AUTH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    self.assertEquals((stem.connection.AuthMethod.PASSWORD, ), control_message.auth_methods)
  
  def test_cookie_auth(self):
    """
    Checks a response with cookie authentication and a path including escape
    characters.
    """
    
    control_message = stem.types.read_message(StringIO.StringIO(COOKIE_AUTH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    self.assertEquals((stem.connection.AuthMethod.COOKIE, ), control_message.auth_methods)
    self.assertEquals("/tmp/my data\\\"dir//control_auth_cookie", control_message.cookie_file)
  
  def test_multiple_auth(self):
    """
    Checks a response with multiple authentication methods.
    """
    
    control_message = stem.types.read_message(StringIO.StringIO(MULTIPLE_AUTH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    self.assertEquals((stem.connection.AuthMethod.COOKIE, stem.connection.AuthMethod.PASSWORD), control_message.auth_methods)
    self.assertEquals("/home/atagar/.tor/control_auth_cookie", control_message.cookie_file)
  
  def test_unknown_auth(self):
    """
    Checks a response with an unrecognized authtentication method.
    """
    
    control_message = stem.types.read_message(StringIO.StringIO(UNKNOWN_AUTH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    self.assertEquals((stem.connection.AuthMethod.UNKNOWN, stem.connection.AuthMethod.PASSWORD), control_message.auth_methods)
    self.assertEquals(("MAGIC", "PIXIE_DUST"), control_message.unknown_auth_methods)
  
  def test_minimum_response(self):
    """
    Checks a PROTOCOLINFO response that only contains the minimum amount of
    information to be a valid response.
    """
    
    control_message = stem.types.read_message(StringIO.StringIO(MINIMUM_RESPONSE))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    
    self.assertEquals(5, control_message.protocol_version)
    self.assertEquals(None , control_message.tor_version)
    self.assertEquals((), control_message.auth_methods)
    self.assertEquals((), control_message.unknown_auth_methods)
    self.assertEquals(None, control_message.cookie_file)
    self.assertEquals(None, control_message.socket)
  
  def test_relative_cookie(self):
    """
    Checks an authentication cookie with a relative path where expansion both
    succeeds and fails.
    """
    
    # we need to mock both pid and cwd lookups since the general cookie
    # expanion works by...
    # - resolving the pid of the "tor" process
    # - using that to get tor's cwd
    
    def call_mocking(command):
      if command == stem.util.system.GET_PID_BY_NAME_PGREP % "tor":
        return ["10"]
      if command == stem.util.system.GET_CWD_PWDX % 10:
        return ["10: /tmp/foo"]
    
    stem.util.system.CALL_MOCKING = call_mocking
    
    control_message = stem.types.read_message(StringIO.StringIO(RELATIVE_COOKIE_PATH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    self.assertEquals("/tmp/foo/tor-browser_en-US/Data/control_auth_cookie", control_message.cookie_file)
    
    # exercise cookie expansion where both calls fail (should work, just
    # leaving the path unexpanded)
    
    stem.util.system.CALL_MOCKING = lambda cmd: None
    control_message = stem.types.read_message(StringIO.StringIO(RELATIVE_COOKIE_PATH))
    stem.connection.ProtocolInfoResponse.convert(control_message)
    self.assertEquals("./tor-browser_en-US/Data/control_auth_cookie", control_message.cookie_file)

