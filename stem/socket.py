"""
Supports message based communication with sockets speaking the tor control
protocol. This lets users send messages as basic strings and receive responses
as instances of the ControlMessage class.

ControlSocket - Socket wrapper that speaks the tor control protocol.
  |- ControlPort - Control connection via a port.
  |  |- get_address - provides the ip address of our socket
  |  +- get_port - provides the port of our socket
  |
  |- ControlSocketFile - Control connection via a local file socket.
  |  +- get_socket_path - provides the path of the socket we connect to
  |
  |- send - sends a message to the socket
  |- recv - receives a ControlMessage from the socket
  |- is_alive - reports if the socket is known to be closed
  |- connect - connects a new socket
  +- close - shuts down the socket

ControlMessage - Message that's read from the control socket.
  |- content - provides the parsed message content
  |- raw_content - unparsed socket data
  |- __str__ - content stripped of protocol formatting
  +- __iter__ - ControlLine entries for the content of the message

ControlLine - String subclass with methods for parsing controller responses.
  |- remainder - provides the unparsed content
  |- is_empty - checks if the remaining content is empty
  |- is_next_quoted - checks if the next entry is a quoted value
  |- is_next_mapping - checks if the next entry is a KEY=VALUE mapping
  |- peek_key - provides the key of the next entry
  |- pop - removes and returns the next entry
  +- pop_mapping - removes and returns the next entry as a KEY=VALUE mapping

send_message - Writes a message to a control socket.
recv_message - Reads a ControlMessage from a control socket.
send_formatting - Performs the formatting expected from sent messages.

ControllerError - Base exception raised when using the controller.
  |- ProtocolError - Malformed socket data.
  +- SocketError - Communication with the socket failed.
     +- SocketClosed - Socket has been shut down.
"""

from __future__ import absolute_import
import re
import socket
import threading

import stem.util.log as log

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

class SocketError(ControllerError):
  "Error arose while communicating with the control socket."

class SocketClosed(SocketError):
  "Control socket was closed before completing the message."

class ControlSocket:
  """
  Wrapper for a socket connection that speaks the Tor control protocol. To the
  better part this transparently handles the formatting for sending and
  receiving complete messages. All methods are thread safe.
  
  Callers should not instantiate this class directly, but rather use subclasses
  which are expected to implement the _make_socket method.
  """
  
  def __init__(self):
    self._socket, self._socket_file = None, None
    self._is_alive = False
    
    # Tracks sending and receiving separately. This should be safe, and doing
    # so prevents deadlock where we block writes because we're waiting to read
    # a message that isn't coming.
    
    self._send_cond = threading.Condition()
    self._recv_cond = threading.Condition()
  
  def send(self, message, raw = False):
    """
    Formats and sends a message to the control socket. For more information see
    the stem.socket.send_message function.
    
    Arguments:
      message (str) - message to be formatted and sent to the socket
      raw (bool)    - leaves the message formatting untouched, passing it to
                      the socket as-is
    
    Raises:
      stem.socket.SocketError if a problem arises in using the socket
      stem.socket.SocketClosed if the socket is known to be shut down
    """
    
    self._send_cond.acquire()
    
    try:
      if not self.is_alive(): raise SocketClosed()
      send_message(self._socket_file, message, raw)
    except SocketClosed, exc:
      # if send_message raises a SocketClosed then we should properly shut
      # everything down
      if self.is_alive(): self.close()
      raise exc
    finally:
      self._send_cond.release()
  
  def recv(self):
    """
    Receives a message from the control socket, blocking until we've received
    one. For more information see the stem.socket.recv_message function.
    
    Returns:
      stem.socket.ControlMessage for the message received
    
    Raises:
      stem.socket.ProtocolError the content from the socket is malformed
      stem.socket.SocketClosed if the socket closes before we receive a
        complete message
    """
    
    self._recv_cond.acquire()
    
    try:
      if not self.is_alive(): raise SocketClosed()
      return recv_message(self._socket_file)
    except SocketClosed, exc:
      # if recv_message raises a SocketClosed then we should properly shut
      # everything down
      if self.is_alive(): self.close()
      raise exc
    finally:
      self._recv_cond.release()
  
  def is_alive(self):
    """
    Checks if the socket is known to be closed. We won't be aware if it is
    until we either use it or have explicitily shut it down.
    
    In practice a socket derived from a port knows about its disconnection
    after a failed recv() call. Socket file derived connections know after
    either a send() or recv().
    
    This means that to have reliable detection for when we're disconnected
    you need to continually pull from the socket (which is part of what the
    BaseController does).
    
    Returns:
      bool that's True if we're known to be shut down and False otherwise
    """
    
    return self._is_alive
  
  def connect(self):
    """
    Connects to a new socket, closing our previous one if we're already
    attached.
    
    Raises:
      stem.socket.SocketError if unable to make a socket
    """
    
    # we need both locks for this
    self._send_cond.acquire()
    self._recv_cond.acquire()
    
    # close the socket if we're currently attached to one
    if self.is_alive(): self.close()
    
    try:
      self._socket = self._make_socket()
      self._socket_file = self._socket.makefile()
      self._is_alive = True
    finally:
      self._send_cond.release()
      self._recv_cond.release()
  
  def close(self):
    """
    Shuts down the socket. If it's already closed then this is a no-op.
    """
    
    # we need both locks for this
    self._send_cond.acquire()
    self._recv_cond.acquire()
    
    if self._socket:
      # if we haven't yet established a connection then this raises an error
      # socket.error: [Errno 107] Transport endpoint is not connected
      try: self._socket.shutdown(socket.SHUT_RDWR)
      except socket.error: pass
      
      # Suppressing unexpected exceptions from close. For instance, if the
      # socket's file has already been closed then with python 2.7 that raises
      # with...
      # error: [Errno 32] Broken pipe
      
      try: self._socket.close()
      except: pass
    
    if self._socket_file:
      try: self._socket_file.close()
      except: pass
    
    self._socket = None
    self._socket_file = None
    self._is_alive = False
    
    self._send_cond.release()
    self._recv_cond.release()
  
  def __enter__(self):
    return self
  
  def __exit__(self, type, value, traceback):
    self.close()
  
  def _make_socket(self):
    """
    Constructs and connects new socket. This is implemented by subclasses.
    
    Returns:
      socket.socket for our configuration
    
    Raises:
      stem.socket.SocketError if unable to make a socket
    """
    
    raise SocketError("Unsupported Operation: this should be implemented by the ControlSocket subclass")

class ControlPort(ControlSocket):
  """
  Control connection to tor. For more information see tor's ControlPort torrc
  option.
  """
  
  def __init__(self, control_addr = "127.0.0.1", control_port = 9051, connect = True):
    """
    ControlPort constructor.
    
    Arguments:
      control_addr (str) - ip address of the controller
      control_port (int) - port number of the controller
      connect (bool)     - connects to the socket if True, leaves it
                           unconnected otherwise
    
    Raises:
      stem.socket.SocketError if connect is True and we're unable to establish
        a connection
    """
    
    ControlSocket.__init__(self)
    self._control_addr = control_addr
    self._control_port = control_port
    
    if connect: self.connect()
  
  def get_address(self):
    """
    Provides the ip address our socket connects to.
    
    Returns:
      str with the ip address of our socket
    """
    
    return self._control_addr
  
  def get_port(self):
    """
    Provides the port our socket connects to.
    
    Returns:
      int with the port of our socket
    """
    
    return self._control_port
  
  def _make_socket(self):
    try:
      control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      control_socket.connect((self._control_addr, self._control_port))
      return control_socket
    except socket.error, exc:
      raise SocketError(exc)

class ControlSocketFile(ControlSocket):
  """
  Control connection to tor. For more information see tor's ControlSocket torrc
  option.
  """
  
  def __init__(self, socket_path = "/var/run/tor/control", connect = True):
    """
    ControlSocketFile constructor.
    
    Arguments:
      socket_path (str) - path where the control socket is located
      connect (bool)     - connects to the socket if True, leaves it
                           unconnected otherwise
    
    Raises:
      stem.socket.SocketError if connect is True and we're unable to establish
        a connection
    """
    
    ControlSocket.__init__(self)
    self._socket_path = socket_path
    
    if connect: self.connect()
  
  def get_socket_path(self):
    """
    Provides the path our socket connects to.
    
    Returns:
      str with the path for our control socket
    """
    
    return self._socket_path
  
  def _make_socket(self):
    try:
      control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      control_socket.connect(self._socket_path)
      return control_socket
    except socket.error, exc:
      raise SocketError(exc)

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
  
  def peek_key(self):
    """
    Provides the key of the next entry, providing None if it isn't a key/value
    mapping.
    
    Returns:
      str with the next entry's key
    """
    
    remainder = self._remainder
    key_match = KEY_ARG.match(remainder)
    
    if key_match:
      return key_match.groups()[0]
    else:
      return None
  
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

def send_message(control_file, message, raw = False):
  """
  Sends a message to the control socket, adding the expected formatting for
  single verses multiline messages. Neither message type should contain an
  ending newline (if so it'll be treated as a multi-line message with a blank
  line at the end). If the message doesn't contain a newline then it's sent
  as...
  
  <message>\r\n
  
  and if it does contain newlines then it's split on \n and sent as...
  
  +<line 1>\r\n
  <line 2>\r\n
  <line 3>\r\n
  .\r\n
  
  Arguments:
    control_file (file) - file derived from the control socket (see the
                          socket's makefile() method for more information)
    message (str)       - message to be sent on the control socket
    raw (bool)          - leaves the message formatting untouched, passing it
                          to the socket as-is
  
  Raises:
    stem.socket.SocketError if a problem arises in using the socket
    stem.socket.SocketClosed if the socket is known to be shut down
  """
  
  if not raw: message = send_formatting(message)
  
  # uses a newline divider if this is a multi-line message (more readable)
  log_message = message.replace("\r\n", "\n").rstrip()
  div = "\n" if "\n" in log_message else " "
  
  try:
    control_file.write(message)
    control_file.flush()
    
    log_message = message.replace("\r\n", "\n").rstrip()
    log.trace("Sent to tor:\n" + log_message)
  except socket.error, exc:
    log.info("Failed to send message: %s" % exc)
    
    # When sending there doesn't seem to be a reliable method for
    # distinguishing between failures from a disconnect verses other things.
    # Just accounting for known disconnection responses.
    
    if str(exc) == "[Errno 32] Broken pipe":
      raise SocketClosed(exc)
    else:
      raise SocketError(exc)
  except AttributeError:
    # if the control_file has been closed then flush will receive:
    # AttributeError: 'NoneType' object has no attribute 'sendall'
    
    log.info("Failed to send message: file has been closed")
    raise SocketClosed("file has been closed")

def recv_message(control_file):
  """
  Pulls from a control socket until we either have a complete message or
  encounter a problem.
  
  Arguments:
    control_file (file) - file derived from the control socket (see the
                          socket's makefile() method for more information)
  
  Returns:
    stem.socket.ControlMessage read from the socket
  
  Raises:
    stem.socket.ProtocolError the content from the socket is malformed
    stem.socket.SocketClosed if the socket closes before we receive a complete
      message
  """
  
  parsed_content, raw_content = [], ""
  logging_prefix = "Error while receiving a control message (%s): "
  
  while True:
    try: line = control_file.readline()
    except AttributeError:
      # if the control_file has been closed then we will receive:
      # AttributeError: 'NoneType' object has no attribute 'recv'
      
      prefix = logging_prefix % "SocketClosed"
      log.info(prefix + "socket file has been closed")
      raise SocketClosed("socket file has been closed")
    except socket.error, exc:
      # when disconnected we get...
      # socket.error: [Errno 107] Transport endpoint is not connected
      
      prefix = logging_prefix % "SocketClosed"
      log.info(prefix + "received exception \"%s\"" % exc)
      raise SocketClosed(exc)
    
    raw_content += line
    
    # Parses the tor control lines. These are of the form...
    # <status code><divider><content>\r\n
    
    if len(line) == 0:
      # if the socket is disconnected then the readline() method will provide
      # empty content
      
      prefix = logging_prefix % "SocketClosed"
      log.info(prefix + "empty socket content")
      raise SocketClosed("Received empty socket content.")
    elif len(line) < 4:
      prefix = logging_prefix % "ProtocolError"
      log.info(prefix + "line too short, \"%s\"" % log.escape(line))
      raise ProtocolError("Badly formatted reply line: too short")
    elif not re.match(r'^[a-zA-Z0-9]{3}[-+ ]', line):
      prefix = logging_prefix % "ProtocolError"
      log.info(prefix + "malformed status code/divider, \"%s\"" % log.escape(line))
      raise ProtocolError("Badly formatted reply line: beginning is malformed")
    elif not line.endswith("\r\n"):
      prefix = logging_prefix % "ProtocolError"
      log.info(prefix + "no CRLF linebreak, \"%s\"" % log.escape(line))
      raise ProtocolError("All lines should end with CRLF")
    
    line = line[:-2] # strips off the CRLF
    status_code, divider, content = line[:3], line[3], line[4:]
    
    if divider == "-":
      # mid-reply line, keep pulling for more content
      parsed_content.append((status_code, divider, content))
    elif divider == " ":
      # end of the message, return the message
      parsed_content.append((status_code, divider, content))
      
      log_message = raw_content.replace("\r\n", "\n").rstrip()
      log.trace("Received from tor:\n" + log_message)
      
      return ControlMessage(parsed_content, raw_content)
    elif divider == "+":
      # data entry, all of the following lines belong to the content until we
      # get a line with just a period
      
      while True:
        try: line = control_file.readline()
        except socket.error, exc:
          prefix = logging_prefix % "SocketClosed"
          log.info(prefix + "received an exception while mid-way through a data reply (exception: \"%s\", read content: \"%s\")" % (exc, log.escape(raw_content)))
          raise SocketClosed(exc)
        
        raw_content += line
        
        if not line.endswith("\r\n"):
          prefix = logging_prefix % "ProtocolError"
          log.info(prefix + "CRLF linebreaks missing from a data reply, \"%s\"" % log.escape(raw_content))
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
      prefix = logging_prefix % "ProtocolError"
      log.warn(prefix + "\"%s\" isn't a recognized divider type" % line)
      raise ProtocolError("Unrecognized divider type '%s': %s" % (divider, line))

def send_formatting(message):
  """
  Performs the formatting expected from sent control messages. For more
  information see the stem.socket.send_message function.
  
  Arguments:
    message (str) - message to be formatted
  
  Returns:
    str of the message wrapped by the formatting expected from controllers
  """
  
  # From control-spec section 2.2...
  #   Command = Keyword OptArguments CRLF / "+" Keyword OptArguments CRLF CmdData
  #   Keyword = 1*ALPHA
  #   OptArguments = [ SP *(SP / VCHAR) ]
  #
  # A command is either a single line containing a Keyword and arguments, or a
  # multiline command whose initial keyword begins with +, and whose data
  # section ends with a single "." on a line of its own.
  
  # if we already have \r\n entries then standardize on \n to start with
  message = message.replace("\r\n", "\n")
  
  if "\n" in message:
    return "+%s\r\n.\r\n" % message.replace("\n", "\r\n")
  else:
    return message + "\r\n"

