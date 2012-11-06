"""
Library for working with the tor process.

**Module Overview:**

::

  ControllerError - Base exception raised when using the controller.
    |- ProtocolError - Malformed socket data.
    |- OperationFailed - Tor was unable to successfully complete the operation.
    |  |- UnsatisfiableRequest - Tor was unable to satisfy a valid request.
    |  +- InvalidRequest - Invalid request.
    |     +- InvalidArguments - Invalid request parameters.
    +- SocketError - Communication with the socket failed.
       +- SocketClosed - Socket has been shut down.
"""

__version__ = '0.0.1'
__author__ = 'Damian Johnson'
__contact__ = 'atagar@torproject.org'
__url__ = 'http://www.atagar.com/stem/'
__license__ = 'LGPLv3'

__all__ = [
  "descriptor",
  "response",
  "util",
  "connection",
  "control",
  "exit_policy",
  "prereq",
  "process",
  "socket",
  "version",
  "ControllerError",
  "ProtocolError",
  "OperationFailed",
  "UnsatisfiableRequest",
  "InvalidRequest",
  "InvalidArguments",
  "SocketError",
  "SocketClosed",
]

class ControllerError(Exception):
  "Base error for controller communication issues."

class ProtocolError(ControllerError):
  "Malformed content from the control socket."

class OperationFailed(ControllerError):
  """
  Base exception class for failed operations that return an error code
  
  :var str code: error code returned by Tor
  :var str message: error message returned by Tor or a human readable error
    message
  """
  
  def __init__(self, code = None, message = None):
    super(ControllerError, self).__init__(message)
    self.code = code
    self.message = message

class UnsatisfiableRequest(OperationFailed):
  """
  Exception raised if Tor was unable to process our request.
  """

class InvalidRequest(OperationFailed):
  """
  Exception raised when the request was invalid or malformed.
  """

class InvalidArguments(InvalidRequest):
  """
  Exception class for requests which had invalid arguments.
  
  :var str code: error code returned by Tor
  :var str message: error message returned by Tor or a human readable error
    message
  :var list arguments: a list of arguments which were invalid
  """
  
  def __init__(self, code = None, message = None, arguments = None):
    super(InvalidArguments, self).__init__(code, message)
    self.arguments = arguments

class SocketError(ControllerError):
  "Error arose while communicating with the control socket."

class SocketClosed(SocketError):
  "Control socket was closed before completing the message."

