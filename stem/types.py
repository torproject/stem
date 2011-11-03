"""
Class representations for a variety of tor objects. These are most commonly
return values rather than being instantiated by users directly.

ProtocolError - Malformed socket data.
ControlSocketClosed - Socket terminated.

read_message - Reads a ControlMessage from a control socket.
ControlMessage - Message from the control socket.
  |- content - provides the parsed message content
  |- raw_content - unparsed socket data
  |- __str__ - content stripped of protocol formatting
  +- __iter__ - message components stripped of protocol formatting

Version - Tor versioning information.
  |- __str__ - string representation
  +- __cmp__ - compares with another Version
"""

import re
import socket

from stem.util import log

# Escape sequences from the 'esc_for_log' function of tor's 'common/util.c'.
CONTROL_ESCAPES = {r"\\": "\\",  r"\"": "\"",   r"\'": "'",
                   r"\r": "\r",  r"\n": "\n",   r"\t": "\t"}

class ProtocolError(Exception):
  "Malformed content from the control socket."
  pass

class ControlSocketClosed(Exception):
  "Control socket was closed before completing the message."
  pass

def read_message(control_file):
  """
  Pulls from a control socket until we either have a complete message or
  encounter a problem.
  
  Arguments:
    control_file - file derived from the control socket (see the socket's
                   makefile() method for more information)
  
  Returns:
    stem.types.ControlMessage read from the socket
  
  Raises:
    ProtocolError the content from the socket is malformed
    ControlSocketClosed if the socket closes before we receive a complete
      message
  """
  
  parsed_content, raw_content = [], ""
  
  while True:
    try: line = control_file.readline()
    except AttributeError, exc:
      # if the control_file has been closed then we will receive:
      # AttributeError: 'NoneType' object has no attribute 'recv'
      
      log.log(log.WARN, "ControlSocketClosed: socket file has been closed")
      raise ControlSocketClosed("socket file has been closed")
    except socket.error, exc:
      log.log(log.WARN, "ControlSocketClosed: received an exception (%s)" % exc)
      raise ControlSocketClosed(exc)
    
    raw_content += line
    
    # Parses the tor control lines. These are of the form...
    # <status code><divider><content>\r\n
    
    if len(line) == 0:
      # if the socket is disconnected then the readline() method will provide
      # empty content
      
      log.log(log.WARN, "ControlSocketClosed: empty socket content")
      raise ControlSocketClosed("Received empty socket content.")
    elif len(line) < 4:
      log.log(log.WARN, "ProtocolError: line too short (%s)" % line)
      raise ProtocolError("Badly formatted reply line: too short")
    elif not re.match(r'^[a-zA-Z0-9]{3}[-+ ]', line):
      log.log(log.WARN, "ProtocolError: malformed status code/divider (%s)" % line)
      raise ProtocolError("Badly formatted reply line: beginning is malformed")
    elif not line.endswith("\r\n"):
      log.log(log.WARN, "ProtocolError: no CRLF linebreak (%s)" % line)
      raise ProtocolError("All lines should end with CRLF")
    
    line = line[:-2] # strips off the CRLF
    status_code, divider, content = line[:3], line[3], line[4:]
    
    if divider == "-":
      # mid-reply line, keep pulling for more content
      parsed_content.append((status_code, divider, content))
    elif divider == " ":
      # end of the message, return the message
      parsed_content.append((status_code, divider, content))
      
      log.log(log.DEBUG, "Received message:\n" + raw_content)
      
      return ControlMessage(parsed_content, raw_content)
    elif divider == "+":
      # data entry, all of the following lines belong to the content until we
      # get a line with just a period
      
      while True:
        try: line = control_file.readline()
        except socket.error, exc: raise ControlSocketClosed(exc)
        
        raw_content += line
        
        if not line.endswith("\r\n"):
          log.log(log.WARN, "ProtocolError: no CRLF linebreak for data entry (%s)" % line)
          raise ProtocolError("All lines should end with CRLF")
        elif line == ".\r\n":
          break # data block termination
        
        line = line[:-2] # strips off the CRLF
        
        # lines starting with a period are escaped by a second period (as per
        # section 2.4 of the control-spec)
        if line.startswith(".."): line = line[1:]
        
        # appends to previous content, using a newline rather than CRLF
        # separator (more conventional for multi-line string content outside
        # the windows world)
        
        content += "\n" + line
      
      parsed_content.append((status_code, divider, content))
    else:
      # this should never be reached due to the prefix regex, but might as well
      # be safe...
      log.log(log.WARN, "ProtocolError: unrecognized divider type (%s)" % line)
      raise ProtocolError("Unrecognized type '%s': %s" % (divider, line))

class ControlMessage:
  """
  Message from the control socket. This is iterable and can be stringified for
  individual message components stripped of protocol formatting.
  """
  
  def __init__(self, parsed_content, raw_content):
    self._parsed_content = parsed_content
    self._raw_content = raw_content
  
  def content(self):
    """
    Provides the parsed message content. These are entries of the form...
    (status_code, divider, content)
    
    * status_code - Three character code for the type of response (defined in
                    section 4 of the control-spec).
    * divider     - Single character to indicate if this is mid-reply, data, or
                    an end to the message (defined in section 2.3 of the
                    control-spec).
    * content     - The following content is the actual payload of the line.
    
    For data entries the content is the full multi-line payload with newline
    linebreaks and leading periods unescaped.
    
    Returns:
      list of (str, str, str) tuples for the components of this message
    """
    
    return list(self._parsed_content)
  
  def raw_content(self):
    """
    Provides the unparsed content read from the control socket.
    
    Returns:
      string of the socket data used to generate this message
    """
    
    return self._raw_content
  
  def __str__(self):
    """
    Content of the message, stripped of status code and divider protocol
    formatting.
    """
    
    return "\n".join(list(self))
  
  def __iter__(self):
    """
    Provides the content of the message (stripped of status codes and dividers)
    for each component of the message. Ie...
    
    250+info/names=
    desc/id/* -- Router descriptors by ID.
    desc/name/* -- Router descriptors by nickname.
    .
    250 OK
    
    Would provide two entries...
    1st - "info/names=
           desc/id/* -- Router descriptors by ID.
           desc/name/* -- Router descriptors by nickname."
    2nd - "OK"
    """
    
    for _, _, content in self._parsed_content:
      yield content

class Version:
  """
  Comparable tor version, as per the 'new version' of the version-spec...
  https://gitweb.torproject.org/torspec.git/blob/HEAD:/version-spec.txt
  
  Attributes:
    major (int)  - major version
    minor (int)  - minor version
    micro (int)  - micro version
    patch (int)  - optional patch level (None if undefined)
    status (str) - optional status tag without the preceding dash such as
                   'alpha', 'beta-dev', etc (None if undefined)
  """
  
  def __init__(self, version_str):
    """
    Parses a valid tor version string, for instance "0.1.4" or
    "0.2.2.23-alpha".
    
    Raises:
      ValueError if input isn't a valid tor version
    """
    
    m = re.match(r'^([0-9]+).([0-9]+).([0-9]+)(.[0-9]+)?(-\S*)?$', version_str)
    
    if m:
      major, minor, micro, patch, status = m.groups()
      
      # The patch and status matches are optional (may be None) and have an extra
      # proceeding period or dash if they exist. Stripping those off.
      
      if patch: patch = int(patch[1:])
      if status: status = status[1:]
      
      self.major = int(major)
      self.minor = int(minor)
      self.micro = int(micro)
      self.patch = patch
      self.status = status
    else: raise ValueError("'%s' isn't a properly formatted tor version" % version_str)
  
  def __str__(self):
    """
    Provides the normal representation for the version, for instance:
    "0.2.2.23-alpha"
    """
    
    suffix = ""
    
    if self.patch:
      suffix += ".%i" % self.patch
    
    if self.status:
      suffix += "-%s" % self.status
    
    return "%i.%i.%i%s" % (self.major, self.minor, self.micro, suffix)
  
  def __cmp__(self, other):
    """
    Simple comparison of versions. An undefined patch level is treated as zero
    and status tags are compared lexically (as per the version spec).
    """
    
    if not isinstance(other, Version):
      raise ValueError("types.Version can only be compared with other Version instances")
    
    for attr in ("major", "minor", "micro", "patch"):
      my_version = max(0, self.__dict__[attr])
      other_version = max(0, other.__dict__[attr])
      
      if my_version > other_version: return 1
      elif my_version < other_version: return -1
    
    my_status = self.status if self.status else ""
    other_status = other.status if other.status else ""
    
    return cmp(my_status, other_status)

# TODO: version requirements will probably be moved to another module later
REQ_GETINFO_CONFIG_TEXT = Version("0.2.2.7-alpha")

# TODO: trying this out temporarily to see if it's generally helpful or another
# parser function would be a better fit
def get_entry(line, mapping = False, quoted = False, escaped = False):
  """
  Parses a space separated series of entries, providing back a tuple with the
  first entry in the string and the remainder (dropping the space between).
  
  This is meant to be a helper function for stem to parse tor's control
  protocol lines rather than being used directly by this library's users.
  
  Example:
    get_entry('hello there random person') =>
      (None, "hello", "there random person")
    get_entry('version="0.1.2.3"', True, True) =>
      ("version", "0.1.2.3", "")
    get_entry('"this has a \" and \\ in it" foo=bar more_data', False, True, True) =>
      (None, 'this has a " and \ in it', "foo=bar more_data")
  
  Arguments:
    line (str)     - string with a space separated series of entries
    mapping (bool) - parses the next entry as a KEY=VALUE entry, if False then
                     the 'key' attribute of the returned tuple is None
    quoted (bool)  - parses the next entry as a quoted value, removing the
                     quotes
    escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
  
  Returns:
    tuple of the form (key, value, remainder)
  
  Raises:
    ValueError if 'mapping' is True without a '=' or 'quoted' is True without
      the value being quoted
  """
  
  # Start by splitting apart the 'key=everything else' portion. The key
  # shouldn't have any spaces in it.
  
  if mapping:
    key_match = re.match("^(\S+)=", line)
    
    if key_match:
      key = key_match.groups()[0]
      remainder = line[key_match.end():]
    else:
      raise ValueError("mapping doesn't contain a '=': " + line)
  else: key, remainder = None, line
  
  if quoted:
    # Check that we have a starting quote.
    if not remainder.startswith("\""):
      raise ValueError("quoted value doesn't have a leading quote: " + line)
    
    # Finds the ending quote. If we have escapes then we need to skip any '\"'
    # entries.
    end_quote = remainder.find("\"", 1)
    
    if escaped:
      while end_quote != -1 and remainder[end_quote - 1] == "\\":
        end_quote = remainder.find("\"", end_quote + 1)
    
    # Check that we have an ending quote.
    if end_quote == -1:
      raise ValueError("quoted value doesn't have an ending quote: " + line)
    
    value, remainder = remainder[1:end_quote], remainder[end_quote + 1:]
  else:
    # Non-quoted value. Just need to check if there's more data afterward.
    if " " in remainder: value, remainder = remainder.split(" ", 1)
    else: value, remainder = remainder, ""
  
  if escaped:
    for esc_sequence, replacement in CONTROL_ESCAPES.items():
      value = value.replace(esc_sequence, replacement)
  
  return (key, value, remainder.lstrip())

