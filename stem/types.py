"""
Class representations for a variety of tor objects. These are most commonly
return values rather than being instantiated by users directly.

ControllerError - Base exception raised when using the controller.
  |- ProtocolError - Malformed socket data.
  |- SocketError - Socket used for controller communication errored.
  +- SocketClosed - Socket terminated.

read_message - Reads a ControlMessage from a control socket.
ControlMessage - Message from the control socket.
  |- content - provides the parsed message content
  |- raw_content - unparsed socket data
  |- __str__ - content stripped of protocol formatting
  +- __iter__ - ControlLine entries for the content of the message

ControlLine - String subclass with methods for parsing controller responses.
  |- remainder - provides the unparsed content
  |- is_empty - checks if the remaining content is empty
  |- is_next_quoted - checks if the next entry is a quoted value
  |- is_next_mapping - checks if the next entry is a KEY=VALUE mapping
  |- pop - removes and returns the next entry
  +- pop_mapping - removes and returns the next entry as a KEY=VALUE mapping

Version - Tor versioning information.
  |- __str__ - string representation
  +- __cmp__ - compares with another Version
"""

import re
import socket
import logging
import threading

LOGGER = logging.getLogger("stem")

KEY_ARG = re.compile("^(\S+)=")

# Escape sequences from the 'esc_for_log' function of tor's 'common/util.c'.
# It's hard to tell what controller functions use this in practice, but direct
# users are...
# - 'COOKIEFILE' field of PROTOCOLINFO responses
# - logged messages about bugs
# - the 'getinfo_helper_listeners' function of control.c which looks to be dead
#   code

CONTROL_ESCAPES = {r"\\": "\\",  r"\"": "\"",   r"\'": "'",
                   r"\r": "\r",  r"\n": "\n",   r"\t": "\t"}

class ControllerError(Exception):
  "Base error for controller communication issues."

class ProtocolError(ControllerError):
  "Malformed content from the control socket."
  pass

class SocketError(ControllerError):
  "Error arose while communicating with the control socket."
  pass

class SocketClosed(ControllerError):
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
    SocketClosed if the socket closes before we receive a complete message
  """
  
  parsed_content, raw_content = [], ""
  
  while True:
    try: line = control_file.readline()
    except AttributeError, exc:
      # if the control_file has been closed then we will receive:
      # AttributeError: 'NoneType' object has no attribute 'recv'
      
      LOGGER.warn("SocketClosed: socket file has been closed")
      raise SocketClosed("socket file has been closed")
    except socket.error, exc:
      LOGGER.warn("SocketClosed: received an exception (%s)" % exc)
      raise SocketClosed(exc)
    
    raw_content += line
    
    # Parses the tor control lines. These are of the form...
    # <status code><divider><content>\r\n
    
    if len(line) == 0:
      # if the socket is disconnected then the readline() method will provide
      # empty content
      
      LOGGER.warn("SocketClosed: empty socket content")
      raise SocketClosed("Received empty socket content.")
    elif len(line) < 4:
      LOGGER.warn("ProtocolError: line too short (%s)" % line)
      raise ProtocolError("Badly formatted reply line: too short")
    elif not re.match(r'^[a-zA-Z0-9]{3}[-+ ]', line):
      LOGGER.warn("ProtocolError: malformed status code/divider (%s)" % line)
      raise ProtocolError("Badly formatted reply line: beginning is malformed")
    elif not line.endswith("\r\n"):
      LOGGER.warn("ProtocolError: no CRLF linebreak (%s)" % line)
      raise ProtocolError("All lines should end with CRLF")
    
    line = line[:-2] # strips off the CRLF
    status_code, divider, content = line[:3], line[3], line[4:]
    
    if divider == "-":
      # mid-reply line, keep pulling for more content
      parsed_content.append((status_code, divider, content))
    elif divider == " ":
      # end of the message, return the message
      parsed_content.append((status_code, divider, content))
      
      LOGGER.debug("Received message:\n" + raw_content)
      
      return ControlMessage(parsed_content, raw_content)
    elif divider == "+":
      # data entry, all of the following lines belong to the content until we
      # get a line with just a period
      
      while True:
        try: line = control_file.readline()
        except socket.error, exc: raise SocketClosed(exc)
        
        raw_content += line
        
        if not line.endswith("\r\n"):
          LOGGER.warn("ProtocolError: no CRLF linebreak for data entry (%s)" % line)
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
      LOGGER.warn("ProtocolError: unrecognized divider type (%s)" % line)
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
    Provides ControlLine instances for the content of the message. This is
    stripped of status codes and dividers, for instance...
    
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
      yield ControlLine(content)

class ControlLine(str):
  """
  String subclass that represents a line of controller output. This behaves as
  a normal string with additional methods for parsing and popping entries from
  a space delimited series of elements like a stack.
  
  None of these additional methods effect ourselves as a string (which is still
  immutable). All methods are thread safe.
  """
  
  def __new__(self, value):
    return str.__new__(self, value)
  
  def __init__(self, value):
    self._remainder = value
    self._remainder_lock = threading.RLock()
  
  def remainder(self):
    """
    Provides our unparsed content. This is an empty string after we've popped
    all entries.
    
    Returns:
      str of the unparsed content
    """
    
    return self._remainder
  
  def is_empty(self):
    """
    Checks if we have further content to pop or not.
    
    Returns:
      True if we have additional content, False otherwise
    """
    
    return self._remainder == ""
  
  def is_next_quoted(self, escaped = False):
    """
    Checks if our next entry is a quoted value or not.
    
    Arguments:
      escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
    
    Returns:
      True if the next entry can be parsed as a quoted value, False otherwise
    """
    
    start_quote, end_quote = _get_quote_indeces(self._remainder, escaped)
    return start_quote == 0 and end_quote != -1
  
  def is_next_mapping(self, key = None, quoted = False, escaped = False):
    """
    Checks if our next entry is a KEY=VALUE mapping or not.
    
    Arguments:
      key (str)      - checks that the key matches this value, skipping the
                       check if None
      quoted (bool)  - checks that the mapping is to a quoted value
      escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
    
    Returns:
      True if the next entry can be parsed as a key=value mapping, False
      otherwise
    """
    
    remainder = self._remainder # temp copy to avoid locking
    key_match = KEY_ARG.match(remainder)
    
    if key_match:
      if key and key != key_match.groups()[0]:
        return False
      
      if quoted:
        # checks that we have a quoted value and that it comes after the 'key='
        start_quote, end_quote = _get_quote_indeces(remainder, escaped)
        return start_quote == key_match.end() and end_quote != -1
      else:
        return True # we just needed to check for the key
    else:
      return False # doesn't start with a key
  
  def pop(self, quoted = False, escaped = False):
    """
    Parses the next space separated entry, removing it and the space from our
    remaining content. Examples...
    
    >>> line = ControlLine("\"We're all mad here.\" says the grinning cat.")
    >>> print line.pop(True)
      "We're all mad here."
    >>> print line.pop()
      "says"
    >>> print line.remainder()
      "the grinning cat."
    
    >>> line = ControlLine("\"this has a \\\" and \\\\ in it\" foo=bar more_data")
    >>> print line.pop(True, True)
      "this has a \" and \\ in it"
    
    Arguments:
      quoted (bool)  - parses the next entry as a quoted value, removing the
                       quotes
      escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
    
    Returns:
      str of the next space separated entry
    
    Raises:
      ValueError if quoted is True without the value being quoted
      IndexError if we don't have any remaining content left to parse
    """
    
    try:
      self._remainder_lock.acquire()
      next_entry, remainder = _parse_entry(self._remainder, quoted, escaped)
      self._remainder = remainder
      return next_entry
    finally:
      self._remainder_lock.release()
  
  def pop_mapping(self, quoted = False, escaped = False):
    """
    Parses the next space separated entry as a KEY=VALUE mapping, removing it
    and the space from our remaining content.
    
    Arguments:
      quoted (bool)  - parses the value as being quoted, removing the quotes
      escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
    
    Returns:
      tuple of the form (key, value)
    
    Raises:
      ValueError if this isn't a KEY=VALUE mapping or if quoted is True without
        the value being quoted
    """
    
    try:
      self._remainder_lock.acquire()
      if self.is_empty(): raise IndexError("no remaining content to parse")
      key_match = KEY_ARG.match(self._remainder)
      
      if not key_match:
        raise ValueError("the next entry isn't a KEY=VALUE mapping: " + self._remainder)
      
      # parse off the key
      key = key_match.groups()[0]
      remainder = self._remainder[key_match.end():]
      
      next_entry, remainder = _parse_entry(remainder, quoted, escaped)
      self._remainder = remainder
      return (key, next_entry)
    finally:
      self._remainder_lock.release()

def _parse_entry(line, quoted, escaped):
  """
  Parses the next entry from the given space separated content.
  
  Arguments:
    line (str)     - content to be parsed
    quoted (bool)  - parses the next entry as a quoted value, removing the
                     quotes
    escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
  
  Returns:
    tuple of the form (entry, remainder)
  
  Raises:
    ValueError if quoted is True without the next value being quoted
    IndexError if there's nothing to parse from the line
  """
  
  if line == "":
    raise IndexError("no remaining content to parse")
  
  next_entry, remainder = "", line
  
  if quoted:
    # validate and parse the quoted value
    start_quote, end_quote = _get_quote_indeces(remainder, escaped)
    
    if start_quote != 0 or end_quote == -1:
      raise ValueError("the next entry isn't a quoted value: " + line)
    
    next_entry, remainder = remainder[1 : end_quote], remainder[end_quote + 1:]
  else:
    # non-quoted value, just need to check if there's more data afterward
    if " " in remainder: next_entry, remainder = remainder.split(" ", 1)
    else: next_entry, remainder = remainder, ""
  
  if escaped:
    for esc_sequence, replacement in CONTROL_ESCAPES.items():
      next_entry = next_entry.replace(esc_sequence, replacement)
  
  return (next_entry, remainder.lstrip())

def _get_quote_indeces(line, escaped):
  """
  Provides the indices of the next two quotes in the given content.
  
  Arguments:
    line (str)     - content to be parsed
    escaped (bool) - unescapes the CONTROL_ESCAPES escape sequences
  
  Returns:
    tuple of two ints, indices being -1 if a quote doesn't exist
  """
  
  indices, quote_index = [], -1
  
  for _ in range(2):
    quote_index = line.find("\"", quote_index + 1)
    
    # if we have escapes then we need to skip any r'\"' entries
    if escaped:
      # skip check if index is -1 (no match) or 0 (first character)
      while quote_index >= 1 and line[quote_index - 1] == "\\":
        quote_index = line.find("\"", quote_index + 1)
    
    indices.append(quote_index)
  
  return tuple(indices)

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
      return 1 # this is also used for equality checks
    
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
REQ_CONTROL_SOCKET = Version("0.2.0.30")

