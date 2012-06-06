"""
Functions for connecting and authenticating to the tor process. Most commonly
you'll either want the 'connect_*' or 'authenticate' function.

The 'connect_*' functions give an easy, one line method for getting an
authenticated control connection. This is handy for CLI applications and the
python interactive interpretor, but does several things that makes it
undesirable for applications (uses stdin/stdout, suppresses exceptions, etc).

The 'authenticate' function, however, gives easy but fine-grained control over
the authentication process. For instance...

::

  import sys
  import getpass
  import stem.connection
  import stem.socket
  
  try:
    control_socket = stem.socket.ControlPort(control_port = 9051)
  except stem.socket.SocketError, exc:
    print "Unable to connect to port 9051 (%s)" % exc
    sys.exit(1)
  
  try:
    stem.connection.authenticate(control_socket)
  except stem.connection.IncorrectSocketType:
    print "Please check in your torrc that 9051 is the ControlPort."
    print "Maybe you configured it to be the ORPort or SocksPort instead?"
    sys.exit(1)
  except stem.connection.MissingPassword:
    controller_password = getpass.getpass("Controller password: ")
    
    try:
      stem.connection.authenticate_password(control_socket, controller_password)
    except stem.connection.PasswordAuthFailed:
      print "Unable to authenticate, password is incorrect"
      sys.exit(1)
  except stem.connection.AuthenticationFailure, exc:
    print "Unable to authenticate: %s" % exc
    sys.exit(1)

**Module Overview:**

::

  connect_port - Convenience method to get an authenticated control connection.
  connect_socket_file - Similar to connect_port, but for control socket files.
  
  authenticate - Main method for authenticating to a control socket.
  authenticate_none - Authenticates to an open control socket.
  authenticate_password - Authenticates to a socket supporting password auth.
  authenticate_cookie - Authenticates to a socket supporting cookie auth.
  
  get_protocolinfo - Issues a PROTOCOLINFO query.
  
  AuthenticationFailure - Base exception raised for authentication failures.
    |- UnrecognizedAuthMethods - Authentication methods are unsupported.
    |- IncorrectSocketType - Socket does not speak the tor control protocol.
    |
    |- OpenAuthFailed - Failure when authenticating by an open socket.
    |  +- OpenAuthRejected - Tor rejected this method of authentication.
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
"""

import os
import getpass
import binascii

import stem.response
import stem.socket
import stem.control
import stem.version
import stem.util.enum
import stem.util.system
import stem.util.log as log
from stem.response.protocolinfo import AuthMethod

def connect_port(control_addr = "127.0.0.1", control_port = 9051, password = None, chroot_path = None, controller = stem.control.Controller):
  """
  Convenience function for quickly getting a control connection. This is very
  handy for debugging or CLI setup, handling setup and prompting for a password
  if necessary (and none is provided). If any issues arise this prints a
  description of the problem and returns None.
  
  :param str control_addr: ip address of the controller
  :param int control_port: port number of the controller
  :param str password: passphrase to authenticate to the socket
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: BaseController subclass to be returned, this provides a ControlSocket if None
  
  :returns: authenticated control connection, the type based on the controller argument
  """
  
  try:
    control_port = stem.socket.ControlPort(control_addr, control_port)
  except stem.socket.SocketError, exc:
    print exc
    return None
  
  return _connect(control_port, password, chroot_path, controller)

def connect_socket_file(socket_path = "/var/run/tor/control", password = None, chroot_path = None, controller = stem.control.Controller):
  """
  Convenience function for quickly getting a control connection. For more
  information see the connect_port function.
  
  :param str socket_path: path where the control socket is located
  :param str password: passphrase to authenticate to the socket
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: BaseController subclass to be returned, this provides a ControlSocket if None
  
  :returns: authenticated control connection, the type based on the controller argument
  """
  
  try:
    control_socket = stem.socket.ControlSocketFile(socket_path)
  except stem.socket.SocketError, exc:
    print exc
    return None
  
  return _connect(control_socket, password, chroot_path, controller)

def _connect(control_socket, password, chroot_path, controller):
  """
  Common implementation for the connect_* functions.
  
  :param stem.socket.ControlSocket control_socket: socket being authenticated to
  :param str password: passphrase to authenticate to the socket
  :param str chroot_path: path prefix if in a chroot environment
  :param Class controller: BaseController subclass to be returned, this provides a ControlSocket if None
  
  :returns: authenticated control connection, the type based on the controller argument
  """
  
  try:
    authenticate(control_socket, password, chroot_path)
    
    if controller == None:
      return control_socket
    else:
      return controller(control_socket)
  except MissingPassword:
    assert password is None, "BUG: authenticate raised MissingPassword despite getting one"
    
    try: password = getpass.getpass("Controller password: ")
    except KeyboardInterrupt: return None
    
    return _connect(control_socket, password, controller)
  except AuthenticationFailure, exc:
    control_socket.close()
    print "Unable to authenticate: %s" % exc
    return None

def authenticate(controller, password = None, chroot_path = None, protocolinfo_response = None):
  """
  Authenticates to a control socket using the information provided by a
  PROTOCOLINFO response. In practice this will often be all we need to
  authenticate, raising an exception if all attempts to authenticate fail.
  
  All exceptions are subclasses of AuthenticationFailure so, in practice,
  callers should catch the types of authentication failure that they care
  about, then have a AuthenticationFailure catch-all at the end.
  
  This can authenticate to either a :class:`stem.control.BaseController` or
  :class:`stem.socket.ControlSocket`.
  
  :param controller: tor controller or socket to be authenticated
  :param str password: passphrase to present to the socket if it uses password authentication (skips password auth if None)
  :param str chroot_path: path prefix if in a chroot environment
  :param stem.response.protocolinfo.ProtocolInfoResponse protocolinfo_response: tor protocolinfo response, this is retrieved on our own if None
  
  :raises: If all attempts to authenticate fails then this will raise a :class:`stem.connection.AuthenticationFailure` subclass. Since this may try multiple authentication methods it may encounter multiple exceptions. If so then the exception this raises is prioritized as follows...
    
    * :class:`stem.connection.IncorrectSocketType`
    
      The controller does not speak the tor control protocol. Most often this
      happened because the user confused the SocksPort or ORPort with the
      ControlPort.
    
    * :class:`stem.connection.UnrecognizedAuthMethods`
    
      All of the authentication methods tor will accept are new and
      unrecognized. Please upgrade stem and, if that doesn't work, file a
      ticket on 'trac.torproject.org' and I'd be happy to add support.
    
    * :class:`stem.connection.MissingPassword`
    
      We were unable to authenticate but didn't attempt password authentication
      because none was provided. You should prompt the user for a password and
      try again via 'authenticate_password'.
    
    * :class:`stem.connection.IncorrectPassword`
    
      We were provided with a password but it was incorrect.
    
    * :class:`stem.connection.IncorrectCookieSize`
    
      Tor allows for authentication by reading it a cookie file, but that file
      is the wrong size to be an authentication cookie.
    
    * :class:`stem.connection.UnreadableCookieFile`
    
      Tor allows for authentication by reading it a cookie file, but we can't
      read that file (probably due to permissions).
    
    * **\***:class:`stem.connection.IncorrectCookieValue`
    
      Tor allows for authentication by reading it a cookie file, but rejected
      the contents of that file.
    
    * **\***:class:`stem.connection.OpenAuthRejected`
    
      Tor says that it allows for authentication without any credentials, but
      then rejected our authentication attempt.
    
    * **\***:class:`stem.connection.MissingAuthInfo`
    
      Tor provided us with a PROTOCOLINFO reply that is technically valid, but
      missing the information we need to authenticate.
    
    * **\***:class:`stem.connection.AuthenticationFailure`
    
      There are numerous other ways that authentication could have failed
      including socket failures, malformed controller responses, etc. These
      mostly constitute transient failures or bugs.
    
    **\*** In practice it is highly unusual for this to occur, being more of a
    theoretical possibility rather than something you should expect. It's fine
    to treat these as errors. If you have a use case where this commonly
    happens, please file a ticket on 'trac.torproject.org'.
    
    In the future new :class:`stem.connection.AuthenticationFailure` subclasses
    may be added to allow for better error handling.
  """
  
  if not protocolinfo_response:
    try:
      protocolinfo_response = get_protocolinfo(controller)
    except stem.socket.ProtocolError:
      raise IncorrectSocketType("unable to use the control socket")
    except stem.socket.SocketError, exc:
      raise AuthenticationFailure("socket connection failed (%s)" % exc)
  
  auth_methods = list(protocolinfo_response.auth_methods)
  auth_exceptions = []
  
  if len(auth_methods) == 0:
    raise NoAuthMethods("our PROTOCOLINFO response did not have any methods for authenticating")
  
  # remove authentication methods that are either unknown or for which we don't
  # have an input
  if AuthMethod.UNKNOWN in auth_methods:
    auth_methods.remove(AuthMethod.UNKNOWN)
    
    unknown_methods = protocolinfo_response.unknown_auth_methods
    plural_label = "s" if len(unknown_methods) > 1 else ""
    methods_label = ", ".join(unknown_methods)
    
    # we... er, can't do anything with only unrecognized auth types
    if not auth_methods:
      exc_msg = "unrecognized authentication method%s (%s)" % (plural_label, methods_label)
      auth_exceptions.append(UnrecognizedAuthMethods(exc_msg, unknown_methods))
    else:
      log.debug("Authenticating to a socket with unrecognized auth method%s, ignoring them: %s" % (plural_label, methods_label))
  
  if AuthMethod.COOKIE in auth_methods and protocolinfo_response.cookie_path is None:
    auth_methods.remove(AuthMethod.COOKIE)
    auth_exceptions.append(NoAuthCookie("our PROTOCOLINFO response did not have the location of our authentication cookie"))
  
  if AuthMethod.PASSWORD in auth_methods and password is None:
    auth_methods.remove(AuthMethod.PASSWORD)
    auth_exceptions.append(MissingPassword("no passphrase provided"))
  
  # iterating over AuthMethods so we can try them in this order
  for auth_type in (AuthMethod.NONE, AuthMethod.PASSWORD, AuthMethod.COOKIE):
    if not auth_type in auth_methods: continue
    
    try:
      if auth_type == AuthMethod.NONE:
        authenticate_none(controller, False)
      elif auth_type == AuthMethod.PASSWORD:
        authenticate_password(controller, password, False)
      elif auth_type == AuthMethod.COOKIE:
        cookie_path = protocolinfo_response.cookie_path
        
        if chroot_path:
          cookie_path = os.path.join(chroot_path, cookie_path.lstrip(os.path.sep))
        
        authenticate_cookie(controller, cookie_path, False)
      
      return # success!
    except OpenAuthRejected, exc:
      auth_exceptions.append(exc)
    except IncorrectPassword, exc:
      auth_exceptions.append(exc)
    except PasswordAuthRejected, exc:
      # Since the PROTOCOLINFO says password auth is available we can assume
      # that if PasswordAuthRejected is raised it's being raised in error.
      log.debug("The authenticate_password method raised a PasswordAuthRejected when password auth should be available. Stem may need to be corrected to recognize this response: %s" % exc)
      auth_exceptions.append(IncorrectPassword(str(exc)))
    except (IncorrectCookieSize, UnreadableCookieFile, IncorrectCookieValue), exc:
      auth_exceptions.append(exc)
    except CookieAuthRejected, exc:
      log.debug("The authenticate_cookie method raised a CookieAuthRejected when cookie auth should be available. Stem may need to be corrected to recognize this response: %s" % exc)
      auth_exceptions.append(IncorrectCookieValue(str(exc), exc.cookie_path))
    except stem.socket.ControllerError, exc:
      auth_exceptions.append(AuthenticationFailure(str(exc)))
  
  # All authentication attempts failed. Raise the exception that takes priority
  # according to our pydocs.
  
  for exc_type in AUTHENTICATE_EXCEPTIONS:
    for auth_exc in auth_exceptions:
      if isinstance(auth_exc, exc_type):
        raise auth_exc
  
  # We really, really shouldn't get here. It means that auth_exceptions is
  # either empty or contains something that isn't an AuthenticationFailure.
  
  raise AssertionError("BUG: Authentication failed without providing a recognized exception: %s" % str(auth_exceptions))

def authenticate_none(controller, suppress_ctl_errors = True):
  """
  Authenticates to an open control socket. All control connections need to
  authenticate before they can be used, even if tor hasn't been configured to
  use any authentication.
  
  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  is_alive() before using the socket further.
  
  This can authenticate to either a :class:`stem.control.BaseController` or
  :class:`stem.socket.ControlSocket`.
  
  *For general usage use the authenticate() function instead.*
  
  :param controller: tor controller or socket to be authenticated
  :param bool suppress_ctl_errors: reports raised :class:`stem.socket.ControllerError` as authentication rejection if True, otherwise they're re-raised
  
  :raises: :class:`stem.connection.OpenAuthRejected` if the empty authentication credentials aren't accepted
  """
  
  try:
    auth_response = _msg(controller, "AUTHENTICATE")
    
    # if we got anything but an OK response then error
    if str(auth_response) != "OK":
      try: controller.connect()
      except: pass
      
      raise OpenAuthRejected(str(auth_response), auth_response)
  except stem.socket.ControllerError, exc:
    try: controller.connect()
    except: pass
    
    if not suppress_ctl_errors: raise exc
    else: raise OpenAuthRejected("Socket failed (%s)" % exc)

def authenticate_password(controller, password, suppress_ctl_errors = True):
  """
  Authenticates to a control socket that uses a password (via the
  HashedControlPassword torrc option). Quotes in the password are escaped.
  
  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  is_alive() before using the socket further.
  
  If you use this function directly, rather than authenticate(), we may
  mistakenly raise a PasswordAuthRejected rather than IncorrectPassword. This
  is because we rely on tor's error messaging which is liable to change in
  future versions (`ticket <https://trac.torproject.org/4817>`_).
  
  This can authenticate to either a :class:`stem.control.BaseController` or
  :class:`stem.socket.ControlSocket`.
  
  *For general usage use the authenticate() function instead.*
  
  :param controller: tor controller or socket to be authenticated
  :param str password: passphrase to present to the socket
  :param bool suppress_ctl_errors: reports raised :class:`stem.socket.ControllerError` as authentication rejection if True, otherwise they're re-raised
  
  :raises:
    * :class:`stem.connection.PasswordAuthRejected` if the socket doesn't accept password authentication
    * :class:`stem.connection.IncorrectPassword` if the authentication credentials aren't accepted
  """
  
  # Escapes quotes. Tor can include those in the password hash, in which case
  # it expects escaped quotes from the controller. For more information see...
  # https://trac.torproject.org/projects/tor/ticket/4600
  
  password = password.replace('"', '\\"')
  
  try:
    auth_response = _msg(controller, "AUTHENTICATE \"%s\"" % password)
    
    # if we got anything but an OK response then error
    if str(auth_response) != "OK":
      try: controller.connect()
      except: pass
      
      # all we have to go on is the error message from tor...
      # Password did not match HashedControlPassword value value from configuration...
      # Password did not match HashedControlPassword *or*...
      
      if "Password did not match HashedControlPassword" in str(auth_response):
        raise IncorrectPassword(str(auth_response), auth_response)
      else:
        raise PasswordAuthRejected(str(auth_response), auth_response)
  except stem.socket.ControllerError, exc:
    try: controller.connect()
    except: pass
    
    if not suppress_ctl_errors: raise exc
    else: raise PasswordAuthRejected("Socket failed (%s)" % exc)

def authenticate_cookie(controller, cookie_path, suppress_ctl_errors = True):
  """
  Authenticates to a control socket that uses the contents of an authentication
  cookie (generated via the CookieAuthentication torrc option). This does basic
  validation that this is a cookie before presenting the contents to the
  socket.
  
  The IncorrectCookieSize and UnreadableCookieFile exceptions take precedence
  over the other types.
  
  If authentication fails tor will disconnect and we'll make a best effort
  attempt to re-establish the connection. This may not succeed, so check
  is_alive() before using the socket further.
  
  If you use this function directly, rather than authenticate(), we may
  mistakenly raise a CookieAuthRejected rather than IncorrectCookieValue. This
  is because we rely on tor's error messaging which is liable to change in
  future versions (`ticket <https://trac.torproject.org/4817>`_).
  
  This can authenticate to either a :class:`stem.control.BaseController` or
  :class:`stem.socket.ControlSocket`.
  
  *For general usage use the authenticate() function instead.*
  
  :param controller: tor controller or socket to be authenticated
  :param str cookie_path: path of the authentication cookie to send to tor
  :param bool suppress_ctl_errors: reports raised :class:`stem.socket.ControllerError` as authentication rejection if True, otherwise they're re-raised
  
  :raises:
    * :class:`stem.connection.IncorrectCookieSize` if the cookie file's size is wrong
    * :class:`stem.connection.UnreadableCookieFile` if the cookie file doesn't exist or we're unable to read it
    * :class:`stem.connection.CookieAuthRejected` if cookie authentication is attempted but the socket doesn't accept it
    * :class:`stem.connection.IncorrectCookieValue` if the cookie file's value is rejected
  """
  
  if not os.path.exists(cookie_path):
    raise UnreadableCookieFile("Authentication failed: '%s' doesn't exist" % cookie_path, cookie_path)
  
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
    exc_msg = "Authentication failed: authentication cookie '%s' is the wrong size (%i bytes instead of 32)" % (cookie_path, auth_cookie_size)
    raise IncorrectCookieSize(exc_msg, cookie_path)
  
  try:
    auth_cookie_file = open(cookie_path, "r")
    auth_cookie_contents = auth_cookie_file.read()
    auth_cookie_file.close()
  except IOError, exc:
    raise UnreadableCookieFile("Authentication failed: unable to read '%s' (%s)" % (cookie_path, exc), cookie_path) 
  
  try:
    msg = "AUTHENTICATE %s" % binascii.b2a_hex(auth_cookie_contents)
    auth_response = _msg(controller, msg)
    
    # if we got anything but an OK response then error
    if str(auth_response) != "OK":
      try: controller.connect()
      except: pass
      
      # all we have to go on is the error message from tor...
      # ... Authentication cookie did not match expected value.
      # ... *or* authentication cookie.
      
      if "*or* authentication cookie." in str(auth_response) or \
         "Authentication cookie did not match expected value." in str(auth_response):
        raise IncorrectCookieValue(str(auth_response), cookie_path, auth_response)
      else:
        raise CookieAuthRejected(str(auth_response), cookie_path, auth_response)
  except stem.socket.ControllerError, exc:
    try: controller.connect()
    except: pass
    
    if not suppress_ctl_errors: raise exc
    else: raise CookieAuthRejected("Socket failed (%s)" % exc, cookie_path)

def get_protocolinfo(controller):
  """
  Issues a PROTOCOLINFO query to a control socket, getting information about
  the tor process running on it. If the socket is already closed then it is
  first reconnected.
  
  According to the control spec the cookie_file is an absolute path. However,
  this often is not the case (especially for the Tor Browser Bundle). If the
  path is relative then we'll make an attempt (which may not work) to correct
  this (`ticket <https://trac.torproject.org/1101>`_).
  
  This can authenticate to either a :class:`stem.control.BaseController` or
  :class:`stem.socket.ControlSocket`.
  
  :param controller: tor controller or socket to be queried
  
  :returns: :class:`stem.response.protocolinfo.ProtocolInfoResponse` provided by tor
  
  :raises:
    * :class:`stem.socket.ProtocolError` if the PROTOCOLINFO response is malformed
    * :class:`stem.socket.SocketError` if problems arise in establishing or using the socket
  """
  
  try:
    protocolinfo_response = _msg(controller, "PROTOCOLINFO 1")
  except:
    protocolinfo_response = None
  
  # Tor hangs up on sockets after receiving a PROTOCOLINFO query if it isn't
  # next followed by authentication. Transparently reconnect if that happens.
  
  if not protocolinfo_response or str(protocolinfo_response) == "Authentication required.":
    controller.connect()
    
    try:
      protocolinfo_response = _msg(controller, "PROTOCOLINFO 1")
    except stem.socket.SocketClosed, exc:
      raise stem.socket.SocketError(exc)
  
  stem.response.convert("PROTOCOLINFO", protocolinfo_response)
  
  # attempt to expand relative cookie paths
  
  if protocolinfo_response.cookie_path:
    stem.connection._expand_cookie_path(protocolinfo_response, stem.util.system.get_pid_by_name, "tor")
  
  # attempt to expand relative cookie paths via the control port or socket file
  
  if isinstance(controller, stem.socket.ControlSocket):
    control_socket = controller
  else:
    control_socket = controller.get_socket()
  
  if isinstance(control_socket, stem.socket.ControlPort):
    if control_socket.get_address() == "127.0.0.1":
      pid_method = stem.util.system.get_pid_by_port
      _expand_cookie_path(protocolinfo_response, pid_method, control_socket.get_port())
  elif isinstance(control_socket, stem.socket.ControlSocketFile):
    pid_method = stem.util.system.get_pid_by_open_file
    _expand_cookie_path(protocolinfo_response, pid_method, control_socket.get_socket_path())
  
  return protocolinfo_response

def _msg(controller, message):
  """
  Sends and receives a message with either a ControlSocket or BaseController.
  """
  
  if isinstance(controller, stem.socket.ControlSocket):
    controller.send(message)
    return controller.recv()
  else:
    return controller.msg(message)

def _expand_cookie_path(protocolinfo_response, pid_resolver, pid_resolution_arg):
  """
  Attempts to expand a relative cookie path with the given pid resolver. This
  leaves the cookie_path alone if it's already absolute, None, or the system
  calls fail.
  """
  
  cookie_path = protocolinfo_response.cookie_path
  if cookie_path and not os.path.isabs(cookie_path):
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
      log.debug("unable to expand relative tor cookie path%s: %s" % (pid_resolver_label, exc))
  
  protocolinfo_response.cookie_path = cookie_path

class AuthenticationFailure(Exception):
  """
  Base error for authentication failures.
  
  :var stem.socket.ControlMessage auth_response: AUTHENTICATE response from the control socket, None if one wasn't received
  """
  
  def __init__(self, message, auth_response = None):
    Exception.__init__(self, message)
    self.auth_response = auth_response

class UnrecognizedAuthMethods(AuthenticationFailure):
  """
  All methods for authenticating aren't recognized.
  
  :var list unknown_auth_methods: authentication methods that weren't recognized
  """
  
  def __init__(self, message, unknown_auth_methods):
    AuthenticationFailure.__init__(self, message)
    self.unknown_auth_methods = unknown_auth_methods

class IncorrectSocketType(AuthenticationFailure):
  "Socket does not speak the control protocol."

class OpenAuthFailed(AuthenticationFailure):
  "Failure to authenticate to an open socket."

class OpenAuthRejected(OpenAuthFailed):
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
  """
  Failure to authenticate with an authentication cookie.
  
  :param str cookie_path: location of the authentication cookie we attempted
  """
  
  def __init__(self, message, cookie_path, auth_response = None):
    AuthenticationFailure.__init__(self, message, auth_response)
    self.cookie_path = cookie_path

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

# authentication exceptions ordered as per the authenticate function's pydocs
AUTHENTICATE_EXCEPTIONS = (
  IncorrectSocketType,
  UnrecognizedAuthMethods,
  MissingPassword,
  IncorrectPassword,
  IncorrectCookieSize,
  UnreadableCookieFile,
  IncorrectCookieValue,
  OpenAuthRejected,
  MissingAuthInfo,
  AuthenticationFailure,
)

