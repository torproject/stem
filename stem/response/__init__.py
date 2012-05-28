"""
Parses replies from the control socket.

converts - translates a ControlMessage into a particular response subclass
"""

__all__ = ["getinfo", "protocolinfo"]

import stem.socket

def convert(response_type, message):
  """
  Converts a ControlMessage into a particular kind of tor response. This does
  an in-place conversion of the message from being a ControlMessage to a
  subclass for its response type. Recognized types include...
  
    * GETINFO
    * PROTOCOLINFO
  
  If the response_type isn't recognized then this is leaves it alone.
  
  Arguments:
    response_type (str)                  - type of tor response to convert to
    message (stem.socket.ControlMessage) - message to be converted
  
  Raises:
    stem.socket.ProtocolError the message isn't a proper response of that type
    TypeError if argument isn't a ControlMessage or response_type isn't
      supported
  """
  
  import stem.response.getinfo
  import stem.response.protocolinfo
  
  if not isinstance(message, stem.socket.ControlMessage):
    raise TypeError("Only able to convert stem.socket.ControlMessage instances")
  
  if response_type == "GETINFO":
    response_class = stem.response.getinfo.GetInfoResponse
  elif response_type == "PROTOCOLINFO":
    response_class = stem.response.protocolinfo.ProtocolInfoResponse
  else: raise TypeError("Unsupported response type: %s" % response_type)
  
  message.__class__ = response_class
  message._parse_message()

