"""
Functions for connecting and authenticating to the tor process.

AuthenticationFailure - Base exception raised for authentication failures.
  |- UnrecognizedAuthMethods - Authentication methods are unsupported.
  |- OpenAuthRejected - Tor rejected this method of authentication.
  |
  |- PasswordAuthFailed - Failure when authenticating by a password.
  |  |- PasswordAuthRejected - Tor rejected this method of authentication.
  |  |- IncorrectPassword - Password was rejected.
  |  +- MissingPassword - Socket supports password auth but wasn't attempted.
  |
  |- CookieAuthFailed - Failure when authenticating by a cookie.
  |  |- CookieAuthRejected - Tor rejected this method of authentication.
  |  |- IncorrectCookieValue - Authentication cookie was rejected.
  |  |- IncorrectCookieSize - Size of the cookie file is incorrect.
  |  +- UnreadableCookieFile - Unable to read the contents of the auth cookie.
  |
  +- MissingAuthInfo - Unexpected PROTOCOLINFO response, missing auth info.
     |- NoAuthMethods - Missing any methods for authenticating.
     +- NoAuthCookie - Supports cookie auth but doesn't have its path.

authenticate - Main method for authenticating to a control socket.
authenticate_none - Authenticates to an open control socket.
authenticate_password - Authenticates to a socket supporting password auth.
authenticate_cookie - Authenticates to a socket supporting cookie auth.

get_protocolinfo_by_port - PROTOCOLINFO query via a control port.
get_protocolinfo_by_socket - PROTOCOLINFO query via a control socket.
ProtocolInfoResponse - Reply from a PROTOCOLINFO query.
  |- Attributes:
  |  |- protocol_version
  |  |- tor_version
  |  |- auth_methods
  |  |- unknown_auth_methods
  |  +- cookie_path
  +- convert - parses a ControlMessage, turning it into a ProtocolInfoResponse
"""

import os
import logging
import binascii

import stem.socket
import stem.version
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

class AuthenticationFailure(Exception):
  """
  Base error for authentication failures.
  
  Attributes:
    auth_response (stem.socket.ControlMessage) - AUTHENTICATE response from
      the control socket, None if one wasn't received
  """
  
  def __init__(self, message, auth_response = None):
    Exception.__init__(self, message)
    self.auth_response = auth_response

class UnrecognizedAuthMethods(AuthenticationFailure):
  "All methods for authenticating aren't recognized."

class OpenAuthRejected(AuthenticationFailure):
  "Attempt to connect to an open control socket was rejected."

class PasswordAuthFailed(AuthenticationFailure):
  "Failure to authenticate with a password."

class PasswordAuthRejected(PasswordAuthFailed):
  "Socket does not support password authentication."

class IncorrectPassword(PasswordAuthFailed):
  "Authentication password incorrect."

class MissingPassword(PasswordAuthFailed):
  "Password authentication is supported but we weren't provided with one."

class CookieAuthFailed(AuthenticationFailure):
  "Failure to authenticate with an authentication cookie."

class CookieAuthRejected(CookieAuthFailed):
  "Socket does not support password authentication."

class IncorrectCookieValue(CookieAuthFailed):
  "Authentication cookie value was rejected."

class IncorrectCookieSize(CookieAuthFailed):
  "Aborted because the cookie file is the wrong size."

class UnreadableCookieFile(CookieAuthFailed):
  "Error arose in reading the authentication cookie."

class MissingAuthInfo(AuthenticationFailure):
  """
  The PROTOCOLINFO response didn't have enough information to authenticate.
  These are valid control responses but really shouldn't happen in practice.
  """

class NoAuthMethods(MissingAuthInfo):
  "PROTOCOLINFO response didn't have any methods for authenticating."

class NoAuthCookie(MissingAuthInfo):
  "PROTOCOLINFO response supports cookie auth but doesn't have its path."

def authenticate_none(control_socket, suppress_ctl_errors = True):
  """
  Authenticates to an open control socket. All control connections need to
  authenticate before they can be used, even if tor hasn't been configured to
  use any authentication.
  
  For general usage use the authenticate function instead. If authentication
  fails then tor will close the control socket.
  
  Arguments:
    control_socket (stem.socket.ControlSocket) - socket to be authenticated
    suppress_ctl_errors (bool) - reports raised stem.socket.ControllerError as
      authentication rejection if True, otherwise they're re-raised
  
  Raises:
    stem.connection.OpenAuthRejected if the empty authentication credentials
      aren't accepted
  """
  
  try:
    control_socket.send("AUTHENTICATE")
    auth_response = control_socket.recv()
    
    # if we got anything but an OK response then error
    if str(auth_response) != "OK":
      control_socket.close()
      raise OpenAuthRejected(str(auth_response), auth_response)
  except stem.socket.ControllerError, exc:
    control_socket.close()
    
    if not suppress_ctl_errors: raise exc
    else: raise OpenAuthRejected("Socket failed (%s)" % exc)

def authenticate_password(control_socket, password, suppress_ctl_errors = True):
  """
  Authenticates to a control socket that uses a password (via the
  HashedControlPassword torrc option). Quotes in the password are escaped.
  
  For general usage use the authenticate function instead. If authentication
  fails then tor will close the control socket.
  
  note: If you use this function directly, rather than authenticate(), we may
  mistakenly raise a PasswordAuthRejected rather than IncorrectPassword. This
  is because we rely on tor's error messaging which is liable to change in
  future versions.
  
  Arguments:
    control_socket (stem.socket.ControlSocket) - socket to be authenticated
    password (str) - passphrase to present to the socket
    suppress_ctl_errors (bool) - reports raised stem.socket.ControllerError as
      authentication rejection if True, otherwise they're re-raised
  
  Raises:
    stem.connection.PasswordAuthRejected if the socket doesn't accept password
      authentication
    stem.connection.IncorrectPassword if the authentication credentials aren't
      accepted
  """
  
  # Escapes quotes. Tor can include those in the password hash, in which case
  # it expects escaped quotes from the controller. For more information see...
  # https://trac.torproject.org/projects/tor/ticket/4600
  
  password = password.replace('"', '\\"')
  
  try:
    control_socket.send("AUTHENTICATE \"%s\"" % password)
    auth_response = control_socket.recv()
    
    # if we got anything but an OK response then error
    if str(auth_response) != "OK":
      control_socket.close()
      
      # all we have to go on is the error message from tor...
      # Password did not match HashedControlPassword value value from configuration...
      # Password did not match HashedControlPassword *or*...
      
      if "Password did not match HashedControlPassword" in str(auth_response):
        raise IncorrectPassword(str(auth_response), auth_response)
      else:
        raise PasswordAuthRejected(str(auth_response), auth_response)
  except stem.socket.ControllerError, exc:
    control_socket.close()
    
    if not suppress_ctl_errors: raise exc
    else: raise PasswordAuthRejected("Socket failed (%s)" % exc)

def authenticate_cookie(control_socket, cookie_path, suppress_ctl_errors = True):
  """
  Authenticates to a control socket that uses the contents of an authentication
  cookie (generated via the CookieAuthentication torrc option). This does basic
  validation that this is a cookie before presenting the contents to the
  socket.
  
  The IncorrectCookieSize and UnreadableCookieFile exceptions take precidence
  over the other types.
  
  For general usage use the authenticate function instead. If authentication
  fails then tor will close the control socket.
  
  note: If you use this function directly, rather than authenticate(), we may
  mistakenly raise a CookieAuthRejected rather than IncorrectCookieValue. This
  is because we rely on tor's error messaging which is liable to change in
  future versions.
  
  Arguments:
    control_socket (stem.socket.ControlSocket) - socket to be authenticated
    cookie_path (str) - path of the authentication cookie to send to tor
    suppress_ctl_errors (bool) - reports raised stem.socket.ControllerError as
      authentication rejection if True, otherwise they're re-raised
  
  Raises:
    stem.connection.IncorrectCookieSize if the cookie file's size is wrong
    stem.connection.UnreadableCookieFile if the cookie file doesn't exist or
      we're unable to read it
    stem.connection.CookieAuthRejected if cookie authentication is attempted
      but the socket doesn't accept it
    stem.connection.IncorrectCookieValue if the cookie file's value is rejected
  """
  
  if not os.path.exists(cookie_path):
    control_socket.close()
    raise UnreadableCookieFile("Authentication failed: '%s' doesn't exist" % cookie_path)
  
  # Abort if the file isn't 32 bytes long. This is to avoid exposing arbitrary
  # file content to the port.
  #
  # Without this a malicious socket could, for instance, claim that
  # '~/.bash_history' or '~/.ssh/id_rsa' was its authentication cookie to trick
  # us into reading it for them with our current permissions.
  #
  # https://trac.torproject.org/projects/tor/ticket/4303
  
  auth_cookie_size = os.path.getsize(cookie_path)
  
  if auth_cookie_size != 32:
    control_socket.close()
    exc_msg = "Authentication failed: authentication cookie '%s' is the wrong size (%i bytes instead of 32)" % (cookie_path, auth_cookie_size)
    raise IncorrectCookieSize(exc_msg)
  
  try:
    auth_cookie_file = open(cookie_path, "r")
    auth_cookie_contents = auth_cookie_file.read()
    auth_cookie_file.close()
  except IOError, exc:
    control_socket.close()
    raise UnreadableCookieFile("Authentication failed: unable to read '%s' (%s)" % (cookie_path, exc)) 
  
  try:
    control_socket.send("AUTHENTICATE %s" % binascii.b2a_hex(auth_cookie_contents))
    auth_response = control_socket.recv()
    
    # if we got anything but an OK response then error
    if str(auth_response) != "OK":
      control_socket.close()
      
      # all we have to go on is the error message from tor...
      # ... Wrong length on authentication cookie.
      # ... *or* authentication cookie.
      
      if "authentication cookie." in str(auth_response):
        raise IncorrectCookieValue(str(auth_response), auth_response)
      else:
        raise CookieAuthRejected(str(auth_response), auth_response)
  except stem.socket.ControllerError, exc:
    control_socket.close()
    
    if not suppress_ctl_errors: raise exc
    else: raise CookieAuthRejected("Socket failed (%s)" % exc)

def get_protocolinfo_by_port(control_addr = "127.0.0.1", control_port = 9051, get_socket = False):
  """
  Issues a PROTOCOLINFO query to a control port, getting information about the
  tor process running on it.
  
  Arguments:
    control_addr (str) - ip address of the controller
    control_port (int) - port number of the controller
    get_socket (bool)  - provides the socket with the response if True,
                         otherwise the socket is closed when we're done
  
  Returns:
    stem.connection.ProtocolInfoResponse provided by tor, if get_socket is True
    then this provides a tuple instead with both the response and connected
    socket (stem.socket.ControlPort)
  
  Raises:
    stem.socket.ProtocolError if the PROTOCOLINFO response is malformed
    stem.socket.SocketError if problems arise in establishing or using the
      socket
  """
  
  try:
    control_socket = stem.socket.ControlPort(control_addr, control_port)
    control_socket.connect()
    control_socket.send("PROTOCOLINFO 1")
    protocolinfo_response = control_socket.recv()
    ProtocolInfoResponse.convert(protocolinfo_response)
    
    # attempt to expand relative cookie paths using our port to infer the pid
    if control_addr == "127.0.0.1":
      _expand_cookie_path(protocolinfo_response, stem.util.system.get_pid_by_port, control_port)
    
    if get_socket:
      return (protocolinfo_response, control_socket)
    else:
      control_socket.close()
      return protocolinfo_response
  except stem.socket.ControllerError, exc:
    control_socket.close()
    raise exc

def get_protocolinfo_by_socket(socket_path = "/var/run/tor/control", get_socket = False):
  """
  Issues a PROTOCOLINFO query to a control socket, getting information about
  the tor process running on it.
  
  Arguments:
    socket_path (str) - path where the control socket is located
    get_socket (bool) - provides the socket with the response if True,
                        otherwise the socket is closed when we're done
  
  Returns:
    stem.connection.ProtocolInfoResponse provided by tor, if get_socket is True
    then this provides a tuple instead with both the response and connected
    socket (stem.socket.ControlSocketFile)
  
  Raises:
    stem.socket.ProtocolError if the PROTOCOLINFO response is malformed
    stem.socket.SocketError if problems arise in establishing or using the
      socket
  """
  
  try:
    control_socket = stem.socket.ControlSocketFile(socket_path)
    control_socket.connect()
    control_socket.send("PROTOCOLINFO 1")
    protocolinfo_response = control_socket.recv()
    ProtocolInfoResponse.convert(protocolinfo_response)
    
    # attempt to expand relative cookie paths using our port to infer the pid
    _expand_cookie_path(protocolinfo_response, stem.util.system.get_pid_by_open_file, socket_path)
    
    if get_socket:
      return (protocolinfo_response, control_socket)
    else:
      control_socket.close()
      return protocolinfo_response
  except stem.socket.ControllerError, exc:
    control_socket.close()
    raise exc

def _expand_cookie_path(protocolinfo_response, pid_resolver, pid_resolution_arg):
  """
  Attempts to expand a relative cookie path with the given pid resolver. This
  leaves the cookie_path alone if it's already absolute, None, or the system
  calls fail.
  """
  
  cookie_path = protocolinfo_response.cookie_path
  if cookie_path and stem.util.system.is_relative_path(cookie_path):
    try:
      tor_pid = pid_resolver(pid_resolution_arg)
      if not tor_pid: raise IOError("pid lookup failed")
      
      tor_cwd = stem.util.system.get_cwd(tor_pid)
      if not tor_cwd: raise IOError("cwd lookup failed")
      
      cookie_path = stem.util.system.expand_path(cookie_path, tor_cwd)
    except IOError, exc:
      resolver_labels = {
        stem.util.system.get_pid_by_name: " by name",
        stem.util.system.get_pid_by_port: " by port",
        stem.util.system.get_pid_by_open_file: " by socket file",
      }
      
      pid_resolver_label = resolver_labels.get(pid_resolver, "")
      LOGGER.debug("unable to expand relative tor cookie path%s: %s" % (pid_resolver_label, exc))
  
  protocolinfo_response.cookie_path = cookie_path

class ProtocolInfoResponse(stem.socket.ControlMessage):
  """
  Version one PROTOCOLINFO query response.
  
  According to the control spec the cookie_file is an absolute path. However,
  this often is not the case (especially for the Tor Browser Bundle)...
  https://trac.torproject.org/projects/tor/ticket/1101
  
  If the path is relative then we'll make an attempt (which may not work) to
  correct this.
  
  The protocol_version is the only mandatory data for a valid PROTOCOLINFO
  response, so all other values are None if undefined or empty if a collection.
  
  Attributes:
    protocol_version (int)             - protocol version of the response
    tor_version (stem.version.Version) - version of the tor process
    auth_methods (tuple)               - AuthMethod types that tor will accept
    unknown_auth_methods (tuple)       - strings of unrecognized auth methods
    cookie_path (str)                  - path of tor's authentication cookie
  """
  
  def convert(control_message):
    """
    Parses a ControlMessage, performing an in-place conversion of it into a
    ProtocolInfoResponse.
    
    Arguments:
      control_message (stem.socket.ControlMessage) -
        message to be parsed as a PROTOCOLINFO reply
    
    Raises:
      stem.socket.ProtocolError the message isn't a proper PROTOCOLINFO response
      TypeError if argument isn't a ControlMessage
    """
    
    if isinstance(control_message, stem.socket.ControlMessage):
      control_message.__class__ = ProtocolInfoResponse
      control_message._parse_message()
      return control_message
    else:
      raise TypeError("Only able to convert stem.socket.ControlMessage instances")
  
  convert = staticmethod(convert)
  
  def _parse_message(self):
    # Example:
    #   250-PROTOCOLINFO 1
    #   250-AUTH METHODS=COOKIE COOKIEFILE="/home/atagar/.tor/control_auth_cookie"
    #   250-VERSION Tor="0.2.1.30"
    #   250 OK
    
    self.protocol_version = None
    self.tor_version = None
    self.cookie_path = None
    
    auth_methods, unknown_auth_methods = [], []
    
    # sanity check that we're a PROTOCOLINFO response
    if not list(self)[0].startswith("PROTOCOLINFO"):
      msg = "Message is not a PROTOCOLINFO response"
      raise stem.socket.ProtocolError(msg)
    
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
          raise stem.socket.ProtocolError(msg)
        
        piversion = line.pop()
        
        if not piversion.isdigit():
          msg = "PROTOCOLINFO response version is non-numeric: %s" % line
          raise stem.socket.ProtocolError(msg)
        
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
          raise stem.socket.ProtocolError(msg)
        
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
          self.cookie_path = line.pop_mapping(True, True)[1]
          
          # attempt to expand relative cookie paths
          _expand_cookie_path(self, stem.util.system.get_pid_by_name, "tor")
      elif line_type == "VERSION":
        # Line format:
        #   VersionLine = "250-VERSION" SP "Tor=" TorVersion OptArguments CRLF
        #   TorVersion = QuotedString
        
        if not line.is_next_mapping("Tor", True):
          msg = "PROTOCOLINFO response's VERSION line is missing its mandatory tor version mapping: %s" % line
          raise stem.socket.ProtocolError(msg)
        
        torversion = line.pop_mapping(True)[1]
        
        try:
          self.tor_version = stem.version.Version(torversion)
        except ValueError, exc:
          raise stem.socket.ProtocolError(exc)
      else:
        LOGGER.debug("unrecognized PROTOCOLINFO line type '%s', ignoring entry: %s" % (line_type, line))
    
    self.auth_methods = tuple(auth_methods)
    self.unknown_auth_methods = tuple(unknown_auth_methods)

