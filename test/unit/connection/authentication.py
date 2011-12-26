"""
Unit tests for the stem.connection.authenticate function.
"""

import StringIO
import functools
import unittest

import stem.connection

# Functors to replace get_protocolinfo and authenticate_*. All of them take any
# number of arguments.
def no_op():
  def _no_op(*args):
    pass
  
  return _no_op

def raise_exception(exception_type):
  if not exception_type: return no_op()
  
  def _raise(exc_type, *args):
    raise exc_type(None)
  
  return functools.partial(_raise, exception_type)

def get_protocolinfo(auth_methods):
  control_message = "250-PROTOCOLINFO 1\r\n250 OK\r\n"
  protocolinfo_response = stem.socket.recv_message(StringIO.StringIO(control_message))
  stem.connection.ProtocolInfoResponse.convert(protocolinfo_response)
  protocolinfo_response.auth_methods = auth_methods
  return lambda *args: protocolinfo_response

def _get_all_auth_method_combinations():
  """
  Enumerates all types of authentication that a PROTOCOLINFO response may
  provide, returning a tuple with the AuthMethod enums.
  """
  
  for is_none in (False, True):
    for is_password in (False, True):
      for is_cookie in (False, True):
        for is_unknown in (False, True):
          auth_methods = []
          
          if is_none: auth_methods.append(stem.connection.AuthMethod.NONE)
          if is_password: auth_methods.append(stem.connection.AuthMethod.PASSWORD)
          if is_cookie: auth_methods.append(stem.connection.AuthMethod.COOKIE)
          if is_unknown: auth_methods.append(stem.connection.AuthMethod.UNKNOWN)
          
          yield tuple(auth_methods)

class TestAuthenticate(unittest.TestCase):
  """
  Under the covers the authentiate function really just translates a
  PROTOCOLINFO response into authenticate_* calls, then does prioritization
  on the exceptions if they all fail.
  
  This monkey patches the various functions authenticate relies on to exercise
  various error conditions, and make sure that the right exception is raised.
  """
  
  def setUp(self):
    # preserves all of the functors we'll need to monkey patch, and make them
    # no-ops
    
    self.original_get_protocolinfo = stem.connection.get_protocolinfo
    self.original_authenticate_none = stem.connection.authenticate_none
    self.original_authenticate_password = stem.connection.authenticate_password
    self.original_authenticate_cookie = stem.connection.authenticate_cookie
    
    stem.connection.get_protocolinfo = no_op()
    stem.connection.authenticate_none = no_op()
    stem.connection.authenticate_password = no_op()
    stem.connection.authenticate_cookie = no_op()
  
  def tearDown(self):
    # restore functions
    stem.connection.get_protocolinfo = self.original_get_protocolinfo
    stem.connection.authenticate_none = self.original_authenticate_none
    stem.connection.authenticate_password = self.original_authenticate_password
    stem.connection.authenticate_cookie = self.original_authenticate_cookie
  
  def test_with_get_protocolinfo(self):
    """
    Tests the authenticate() function when it needs to make a get_protocolinfo.
    """
    
    # tests where get_protocolinfo succeeds
    stem.connection.get_protocolinfo = get_protocolinfo((stem.connection.AuthMethod.NONE, ))
    stem.connection.authenticate(None)
    
    # tests where get_protocolinfo raises a ProtocolError
    stem.connection.get_protocolinfo = raise_exception(stem.socket.ProtocolError)
    self.assertRaises(stem.connection.IncorrectSocketType, stem.connection.authenticate, None)
    
    # tests where get_protocolinfo raises a SocketError
    stem.connection.get_protocolinfo = raise_exception(stem.socket.SocketError)
    self.assertRaises(stem.connection.AuthenticationFailure, stem.connection.authenticate, None)
  
  def test_all_use_cases(self):
    """
    Does basic validation that all valid use cases for the PROTOCOLINFO input
    and dependent functions result in either success or a AuthenticationFailed
    subclass being raised.
    """
    
    # exceptions that the authentication functions are documented to raise
    auth_none_exc_types = (None,
      stem.connection.OpenAuthRejected)
    
    auth_password_exc_types = (None,
      stem.connection.PasswordAuthRejected,
      stem.connection.IncorrectPassword)
    
    auth_cookie_exc_types = (None,
      stem.connection.IncorrectCookieSize,
      stem.connection.UnreadableCookieFile,
      stem.connection.CookieAuthRejected,
      stem.connection.IncorrectCookieValue)
    
    # auth functions don't suppress controller exceptions
    control_exc_types = (
      stem.socket.ProtocolError,
      stem.socket.SocketError,
      stem.socket.SocketClosed)
    
    for auth_methods in _get_all_auth_method_combinations():
      protocolinfo_input = get_protocolinfo(auth_methods)()
      
      for auth_none_exc in auth_none_exc_types + control_exc_types:
        for auth_password_exc in auth_password_exc_types + control_exc_types:
          for auth_cookie_exc in auth_cookie_exc_types + control_exc_types:
            stem.connection.authenticate_none = raise_exception(auth_none_exc)
            stem.connection.authenticate_password = raise_exception(auth_password_exc)
            stem.connection.authenticate_cookie = raise_exception(auth_cookie_exc)
            
            # calling authenticate should either succeed or raise a
            # AuthenticationFailure subclass
            
            try:
              stem.connection.authenticate(None, protocolinfo_response = protocolinfo_input)
            except stem.connection.AuthenticationFailure:
              pass

