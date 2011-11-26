"""
Functions for connecting and authenticating to the tor process.

get_protocolinfo_by_port - PROTOCOLINFO query via a control port.
get_protocolinfo_by_socket - PROTOCOLINFO query via a control socket.
ProtocolInfoResponse - Reply from a PROTOCOLINFO query.
  |- Attributes:
  |  |- protocol_version
  |  |- tor_version
  |  |- auth_methods
  |  |- unknown_auth_methods
  |  |- cookie_path
  |  +- socket
  +- convert - parses a ControlMessage, turning it into a ProtocolInfoResponse
"""

from __future__ import absolute_import
import Queue
import socket
import logging
import threading

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

def get_protocolinfo_by_port(control_addr = "127.0.0.1", control_port = 9051, keep_alive = False):
  """
  Issues a PROTOCOLINFO query to a control port, getting information about the
  tor process running on it.
  
  Arguments:
    control_addr (str) - ip address of the controller
    control_port (int) - port number of the controller
    keep_alive (bool)  - keeps the socket used to issue the PROTOCOLINFO query
                         open if True, closes otherwise
  
  Returns:
    ProtocolInfoResponse with the response given by the tor process
  
  Raises:
    stem.socket.ProtocolError if the PROTOCOLINFO response is malformed
    stem.socket.SocketError if problems arise in establishing or using the
      socket
  """
  
  control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connection_args = (control_addr, control_port)
  protocolinfo_response = _get_protocolinfo_impl(control_socket, connection_args, keep_alive)
  
  # attempt to expand relative cookie paths using our port to infer the pid
  protocolinfo_response.cookie_path = _expand_cookie_path(protocolinfo_response.cookie_path, stem.util.system.get_pid_by_port, control_port)
  
  return protocolinfo_response

def get_protocolinfo_by_socket(socket_path = "/var/run/tor/control", keep_alive = False):
  """
  Issues a PROTOCOLINFO query to a control socket, getting information about
  the tor process running on it.
  
  Arguments:
    socket_path (str) - path where the control socket is located
    keep_alive (bool) - keeps the socket used to issue the PROTOCOLINFO query
                        open if True, closes otherwise
  
  Raises:
    stem.socket.ProtocolError if the PROTOCOLINFO response is malformed
    stem.socket.SocketError if problems arise in establishing or using the
      socket
  """
  
  control_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  protocolinfo_response = _get_protocolinfo_impl(control_socket, socket_path, keep_alive)
  
  # attempt to expand relative cookie paths using our socket to infer the pid
  protocolinfo_response.cookie_path = _expand_cookie_path(protocolinfo_response.cookie_path, stem.util.system.get_pid_by_open_file, socket_path)
  
  return protocolinfo_response

def _get_protocolinfo_impl(control_socket, connection_args, keep_alive):
  """
  Common implementation behind the get_protocolinfo_by_* functions. This
  connects the given socket and issues a PROTOCOLINFO query with it.
  """
  
  try:
    control_socket.connect(connection_args)
    control_socket = stem.socket.ControlSocket(control_socket)
  except socket.error, exc:
    raise stem.socket.SocketError(exc)
  
  try:
    control_socket.send("PROTOCOLINFO 1")
    protocolinfo_response = control_socket.recv()
    ProtocolInfoResponse.convert(protocolinfo_response)
    
    if keep_alive: protocolinfo_response.socket = control_socket
    else: control_socket.close()
    
    return protocolinfo_response
  except stem.socket.ControllerError, exc:
    control_socket.close()
    raise exc

def _expand_cookie_path(cookie_path, pid_resolver, pid_resolution_arg):
  """
  Attempts to expand a relative cookie path with the given pid resolver. This
  returns the input path if it's already absolute, None, or the system calls
  fail.
  """
  
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
  
  return cookie_path

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
    socket (stem.socket.ControlSocket) - socket used to make the query
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
    self.socket = None
    
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
          self.cookie_path = _expand_cookie_path(self.cookie_path, stem.util.system.get_pid_by_name, "tor")
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

