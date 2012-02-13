"""
Classes for interacting with the tor control socket.

Controllers are a wrapper around a ControlSocket, retaining many of its methods
(send, recv, is_alive, etc) in addition to providing its own for interacting at
a higher level.

from_port - Provides a Controller based on a port connection.
from_socket_file - Provides a Controller based on a socket file connection.

BaseController - Base controller class asynchronous message handling.
  |- is_alive - reports if the socket is known to be closed
  |- connect - connects a new socket
  |- close - shuts down the socket
  |- get_socket - provides socket providing base control communication
  |- add_status_listener - notifies a callback of changes in the socket status
  +- remove_status_listener - prevents further notification of status changes
"""

import time
import thread
import threading

import stem.socket

# state changes a control socket can have
# INIT   - new control connection
# RESET  - received a reset/sighup signal
# CLOSED - control connection closed

State = stem.util.enum.Enum("INIT", "RESET", "CLOSED")

class BaseController:
  """
  Controller for the tor process. This is a minimal base class for other
  controllers, providing basic process communication and event listing. Don't
  use this directly - subclasses provide higher level functionality.
  
  Do not continue to directly interacte with the ControlSocket we're
  constructed from - use our wrapper methods instead.
  """
  
  # TODO: Convenience methods for the BaseController are pointless since
  # callers generally won't want to make instances of this directly. Move
  # these to the Controller class once we have one.
  
  def from_port(control_addr = "127.0.0.1", control_port = 9051):
    """
    Constructs a ControlPort based Controller.
    
    Arguments:
      control_addr (str) - ip address of the controller
      control_port (int) - port number of the controller
    
    Returns:
      stem.control.Controller attached to the given port
    
    Raises:
      stem.socket.SocketError if we're unable to establish a connection
    """
    
    control_port = stem.socket.ControlPort(control_addr, control_port)
    return BaseController(control_port)
  
  def from_socket_file(socket_path = "/var/run/tor/control"):
    """
    Constructs a ControlSocketFile based Controller.
    
    Arguments:
      socket_path (str) - path where the control socket is located
    
    Returns:
      stem.control.Controller attached to the given socket file
    
    Raises:
      stem.socket.SocketError if we're unable to establish a connection
    """
    
    control_socket = stem.socket.ControlSocketFile(socket_path)
    return BaseController(control_socket)
  
  from_port = staticmethod(from_port)
  from_socket_file = staticmethod(from_socket_file)
  
  def __init__(self, control_socket):
    self._socket = control_socket
    
    self._status_listeners = [] # tuples of the form (callback, spawn_thread)
    self._status_listeners_lock = threading.RLock()
    
    # saves our socket's prior _connect() and _close() methods so they can be
    # called along with ours
    
    self._socket_connect = self._socket._connect
    self._socket_close = self._socket._close
    
    self._socket._connect = self._connect
    self._socket._close = self._close
  
  def is_alive(self):
    """
    Checks if our socket is currently connected. This is a passthrough for our
    socket's is_alive() method.
    
    Returns:
      bool that's True if we're shut down and False otherwise
    """
    
    return self._socket.is_alive()
  
  def connect(self):
    """
    Reconnects our control socket. This is a passthrough for our socket's
    connect() method.
    
    Raises:
      stem.socket.SocketError if unable to make a socket
    """
    
    self._socket.connect()
  
  def close(self):
    """
    Closes our socket connection. This is a passthrough for our socket's
    close() method.
    """
    
    self._socket.close()
  
  def get_socket(self):
    """
    Provides the socket used to speak with the tor process. Communicating with
    the socket directly isn't advised since it may confuse the controller.
    
    Returns:
      ControlSocket for process communications
    """
    
    return self._socket
  
  def add_status_listener(self, callback, spawn = True):
    """
    Notifies a given function when the state of our socket changes. Functions
    are expected to be of the form...
    
      my_function(controller, state, timestamp)
    
    The state is a value from stem.socket.State, functions *must* allow for
    new values in this field. The timestamp is a float for the unix time when
    the change occured.
    
    This class only provides State.INIT and State.CLOSED notifications.
    Subclasses may provide others.
    
    If spawn is True then the callback is notified via a new daemon thread. If
    false then the notice is under our locks, within the thread where the
    change occured. In general this isn't advised, especially if your callback
    could block for a while.
    
    Arguments:
      callback (function) - function to be notified when our state changes
      spawn (bool)        - calls function via a new thread if True, otherwise
                            it's part of the connect/close method call
    """
    
    with self._status_listeners_lock:
      self._status_listeners.append((callback, spawn))
  
  def remove_status_listener(self, callback):
    """
    Stops listener from being notified of further events.
    
    Arguments:
      callback (function) - function to be removed from our listeners
    
    Returns:
      bool that's True if we removed one or more occurances of the callback,
      False otherwise
    """
    
    with self._status_listeners_lock:
      new_listeners, is_changed = [], False
      
      for listener, spawn in self._status_listeners:
        if listener != callback:
          new_listeners.append((listener, spawn))
        else: is_changed = True
      
      self._status_listeners = new_listeners
      return is_changed
  
  def _connect(self):
    self._notify_status_listeners(State.INIT, True)
    self._socket_connect()
  
  def _close(self):
    self._notify_status_listeners(State.CLOSED, False)
    self._socket_close()
  
  def _notify_status_listeners(self, state, expect_alive = None):
    """
    Informs our status listeners that a state change occured.
    
    States imply that our socket is either alive or not, which may not hold
    true when multiple events occure in quick succession. For instance, a
    sighup could cause two events (State.RESET for the sighup and State.CLOSE
    if it causes tor to crash). However, there's no guarentee of the order in
    which they occure, and it would be bad if listeners got the State.RESET
    last, implying that we were alive.
    
    If set, the expect_alive flag will discard our event if it conflicts with
    our current is_alive() state.
    
    Arguments:
      state (stem.socket.State) - state change that has occured
      expect_alive (bool)       - discard event if it conflicts with our
                                  is_alive() state
    """
    
    # Our socket's calles (the connect() and close() methods) already acquire
    # these locks. However, our subclasses that use this method probably won't
    # have them, so locking to prevent those from conflicting with each other
    # and connect() / close().
    
    with self._socket._send_lock, self._socket._recv_lock, self._status_listeners_lock:
      change_timestamp = time.time()
      
      if expect_alive != None and expect_alive != self.is_alive():
        return
      
      for listener, spawn in self._status_listeners:
        if spawn:
          thread.start_new_thread(listener, (self, state, change_timestamp))
        else:
          listener(self, state, change_timestamp)

