"""
Functions for connecting and authenticating to the tor process.
"""

import Queue
import socket
import logging
import threading

import stem.types
import stem.util.enum
import stem.util.system

LOGGER = logging.getLogger("stem")

# Methods by which a controller can authenticate to the control port. Tor gives
# a list of all the authentication methods it will accept in response to
# PROTOCOLINFO queries.
#
# NONE     - No authentication required
# PASSWORD - See tor's HashedControlPassword option. Controllers must provide
#            the password used to generate the hash.
# COOKIE   - See tor's CookieAuthentication option. Controllers need to supply
#            the contents of the cookie file.
# UNKNOWN  - Tor provided one or more authentication methods that we don't
#            recognize. This is probably from a new addition to the control
#            protocol.

AuthMethod = stem.util.enum.Enum("NONE", "PASSWORD", "COOKIE", "UNKNOWN")

class ProtocolInfoResponse(stem.types.ControlMessage):
  """
  Version one PROTOCOLINFO query response.
  
  According to the control spec the cookie_file is an absolute path. However,
  this often is not the case (especially for the Tor Browser Bundle)...
  https://trac.torproject.org/projects/tor/ticket/1101
  
  If the path is relative then we'll make an attempt (which may not work) to
  correct this.
  
  The protocol_version is the only mandatory data for a valid PROTOCOLINFO
  response, so all other values are None if undefined or empty if a collecion.
  
  Attributes:
    protocol_version (int)           - protocol version of the response
    tor_version (stem.types.Version) - version of the tor process
    auth_methods (tuple)             - AuthMethod types that tor will accept
    unknown_auth_methods (tuple)     - strings of unrecognized auth methods
    cookie_file (str)                - path of tor's authentication cookie
    socket (socket.socket)           - socket used to make the query
  """
  
  def convert(control_message):
    """
    Parses a ControlMessage, converting it into a ProtocolInfoResponse.
    
    Arguments:
      control_message (stem.types.ControlMessage) -
        message to be parsed as a PROTOCOLINFO reply
    
    Raises:
      stem.types.ProtocolError the message isn't a proper PROTOCOLINFO response
      ValueError if argument is of the wrong type
    """
    
    if isinstance(control_message, stem.types.ControlMessage):
      control_message.__class__ = ProtocolInfoResponse
      control_message._parse_message()
      return control_message
    else:
      raise ValueError("Only able to convert stem.types.ControlMessage instances")
  
  convert = staticmethod(convert)
  
  def _parse_message(self):
    # Example:
    #   250-PROTOCOLINFO 1
    #   250-AUTH METHODS=COOKIE COOKIEFILE="/home/atagar/.tor/control_auth_cookie"
    #   250-VERSION Tor="0.2.1.30"
    #   250 OK
    
    self.protocol_version = None
    self.tor_version = None
    self.cookie_file = None
    self.socket = None
    
    auth_methods, unknown_auth_methods = [], []
    
    # sanity check that we're a PROTOCOLINFO response
    if not list(self)[0].startswith("PROTOCOLINFO"):
      msg = "Message is not a PROTOCOLINFO response"
      raise stem.types.ProtocolError(msg)
    
    for line in self:
      if line == "OK": break
      elif line.is_empty(): continue # blank line
      
      line_type = line.pop()
      
      if line_type == "PROTOCOLINFO":
        # Line format:
        #   FirstLine = "PROTOCOLINFO" SP PIVERSION CRLF
        #   PIVERSION = 1*DIGIT
        
        if line.is_empty():
          msg = "PROTOCOLINFO response's initial line is missing the protocol version: %s" % line
          raise stem.types.ProtocolError(msg)
        
        piversion = line.pop()
        
        if not piversion.isdigit():
          msg = "PROTOCOLINFO response version is non-numeric: %s" % line
          raise stem.types.ProtocolError(msg)
        
        self.protocol_version = int(piversion)
        
        # The piversion really should be "1" but, according to the spec, tor
        # does not necessarily need to provide the PROTOCOLINFO version that we
        # requested. Log if it's something we aren't expecting but still make
        # an effort to parse like a v1 response.
        
        if self.protocol_version != 1:
          LOGGER.warn("We made a PROTOCOLINFO v1 query but got a version %i response instead. We'll still try to use it, but this may cause problems." % self.protocol_version)
      elif line_type == "AUTH":
        # Line format:
        #   AuthLine = "250-AUTH" SP "METHODS=" AuthMethod *("," AuthMethod)
        #              *(SP "COOKIEFILE=" AuthCookieFile) CRLF
        #   AuthMethod = "NULL" / "HASHEDPASSWORD" / "COOKIE"
        #   AuthCookieFile = QuotedString
        
        # parse AuthMethod mapping
        if not line.is_next_mapping("METHODS"):
          msg = "PROTOCOLINFO response's AUTH line is missing its mandatory 'METHODS' mapping: %s" % line
          raise stem.types.ProtocolError(msg)
        
        for method in line.pop_mapping()[1].split(","):
          if method == "NULL":
            auth_methods.append(AuthMethod.NONE)
          elif method == "HASHEDPASSWORD":
            auth_methods.append(AuthMethod.PASSWORD)
          elif method == "COOKIE":
            auth_methods.append(AuthMethod.COOKIE)
          else:
            unknown_auth_methods.append(method)
            LOGGER.info("PROTOCOLINFO response had an unrecognized authentication method: %s" % method)
            
            # our auth_methods should have a single AuthMethod.UNKNOWN entry if
            # any unknown authentication methods exist
            if not AuthMethod.UNKNOWN in auth_methods:
              auth_methods.append(AuthMethod.UNKNOWN)
        
        # parse optional COOKIEFILE mapping (quoted and can have escapes)
        if line.is_next_mapping("COOKIEFILE", True, True):
          self.cookie_file = line.pop_mapping(True, True)[0]
          
          # attempt to expand relative cookie paths
          if stem.util.system.is_relative_path(self.cookie_file):
            try:
              tor_pid = stem.util.system.get_pid("tor", suppress_exc = False)
              tor_cwd = stem.util.system.get_cwd(tor_pid, False)
              self.cookie_file = stem.util.system.expand_path(self.cookie_file, tor_cwd)
            except IOError, exc:
              LOGGER.debug("unable to expand relative tor cookie path: %s" % exc)
      elif line_type == "VERSION":
        # Line format:
        #   VersionLine = "250-VERSION" SP "Tor=" TorVersion OptArguments CRLF
        #   TorVersion = QuotedString
        
        if not line.is_next_mapping("Tor", True):
          msg = "PROTOCOLINFO response's VERSION line is missing its mandatory tor version mapping: %s" % line
          raise stem.types.ProtocolError(msg)
        
        torversion = line.pop_mapping(True)[1]
        
        try:
          self.tor_version = stem.types.Version(torversion)
        except ValueError, exc:
          raise stem.types.ProtocolError(exc)
      else:
        LOGGER.debug("unrecognized PROTOCOLINFO line type '%s', ignoring entry: %s" % (line_type, line))
    
    self.auth_methods = tuple(auth_methods)
    self.unknown_auth_methods = tuple(unknown_auth_methods)

class ControlConnection:
  """
  Connection to a Tor control port. This is a very lightweight wrapper around
  the socket, providing basic process communication and event listening. Don't
  use this directly - subclasses provide friendlier controller access.
  """
  
  def __init__(self, control_socket):
    self._is_running = True
    self._control_socket = control_socket
    
    # File accessor for far better sending and receiving functionality. This
    # uses a duplicate file descriptor so both this and the socket need to be
    # closed when done.
    
    self._control_socket_file = self._control_socket.makefile()
    
    # queues where messages from the control socket are directed
    self._event_queue = Queue.Queue()
    self._reply_queue = Queue.Queue()
    
    # prevents concurrent writing to the socket
    self._socket_write_cond = threading.Condition()
    
    # thread to pull from the _event_queue and call handle_event
    self._event_cond = threading.Condition()
    self._event_thread = threading.Thread(target = self._event_loop)
    self._event_thread.setDaemon(True)
    self._event_thread.start()
    
    # thread to continually pull from the control socket
    self._reader_thread = threading.Thread(target = self._reader_loop)
    self._reader_thread.setDaemon(True)
    self._reader_thread.start()
  
  def is_running(self):
    """
    True if we still have an open connection to the control socket, false
    otherwise.
    """
    
    return self._is_running
  
  def handle_event(self, event_message):
    """
    Overwritten by subclasses to provide event listening. This is notified
    whenever we receive an event from the control socket.
    
    Arguments:
      event_message (stem.types.ControlMessage) -
          message received from the control socket
    """
    
    pass
  
  def send(self, message):
    """
    Sends a message to the control socket and waits for a reply.
    
    Arguments:
      message (str) - message to be sent to the control socket
    
    Returns:
      stem.types.ControlMessage with the response from the control socket
    """
    
    # makes sure that the message ends with a CRLF
    message = message.rstrip("\r\n") + "\r\n"
    
    self._socket_write_cond.acquire()
    self._control_socket_file.write(message)
    self._control_socket_file.flush()
    self._socket_write_cond.release()
    
    return self._reply_queue.get()
  
  def _event_loop(self):
    """
    Continually pulls messages from the _event_thread and sends them to
    handle_event. This is done via its own thread so subclasses with a lengthy
    handle_event implementation don't block further reading from the socket.
    """
    
    while self.is_running():
      try:
        event_message = self._event_queue.get_nowait()
        self.handle_event(event_message)
      except Queue.Empty:
        self._event_cond.acquire()
        self._event_cond.wait()
        self._event_cond.release()
  
  def _reader_loop(self):
    """
    Continually pulls from the control socket, directing the messages into
    queues based on their type. Controller messages come in two varieties...
    
    - Responses to messages we've sent (GETINFO, SETCONF, etc).
    - Asynchronous events, identified by a status code of 650.
    """
    
    while self.is_running():
      try:
        control_message = stem.types.read_message(self._control_socket_file)
        
        if control_message.content()[-1][0] == "650":
          # adds this to the event queue and wakes up the handler
          
          self._event_cond.acquire()
          self._event_queue.put(control_message)
          self._event_cond.notifyAll()
          self._event_cond.release()
        else:
          # TODO: figure out a good method for terminating the socket thread
          self._reply_queue.put(control_message)
      except stem.types.ProtocolError, exc:
        LOGGER.error("Error reading control socket message: %s" % exc)
        # TODO: terminate?
  
  def close(self):
    """
    Terminates the control connection.
    """
    
    self._is_running = False
    
    # if we haven't yet established a connection then this raises an error
    # socket.error: [Errno 107] Transport endpoint is not connected
    try: self._control_socket.shutdown(socket.SHUT_RDWR)
    except socket.error: pass
    
    self._control_socket.close()
    self._control_socket_file.close()
    
    # wake up the event thread so it can terminate
    self._event_cond.acquire()
    self._event_cond.notifyAll()
    self._event_cond.release()
    
    self._event_thread.join()
    self._reader_thread.join()

# temporary function for getting a connection
def test_connection():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect(("127.0.0.1", 9051))
  return ControlConnection(s)

