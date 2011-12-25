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
    raise exc_type
  
  return functools.partial(_raise, exception_type)

def get_protocolinfo(auth_methods):
  control_message = "250-PROTOCOLINFO 1\r\n250 OK\r\n"
  protocolinfo_response = stem.socket.recv_message(StringIO.StringIO(control_message))
  stem.connection.ProtocolInfoResponse.convert(protocolinfo_response)
  protocolinfo_response.auth_methods = auth_methods
  return lambda *args: protocolinfo_response

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

