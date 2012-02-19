"""
Classes for interacting with the tor control socket.

Controllers are a wrapper around a ControlSocket, retaining many of its methods
(send, recv, is_alive, etc) in addition to providing its own for interacting at
a higher level.

from_port - Provides a Controller based on a port connection.
from_socket_file - Provides a Controller based on a socket file connection.

BaseController - Base controller class asynchronous message handling.
  |- msg - communicates with the tor process
  |- is_alive - reports if our connection to tor is open or closed
  |- connect - connects or reconnects to tor
  |- close - shuts down our connection to the tor process
  |- get_socket - provides the socket used for control communication
  |- add_status_listener - notifies a callback of changes in our status
  +- remove_status_listener - prevents further notification of status changes
"""

import time
import Queue
import threading

import stem.socket
import stem.util.log as log

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
    self._msg_lock = threading.RLock()
    
    self._status_listeners = [] # tuples of the form (callback, spawn_thread)
    self._status_listeners_lock = threading.RLock()
    
    # queues where incoming messages are directed
    self._reply_queue = Queue.Queue()
    self._event_queue = Queue.Queue()
    
    # thread to continually pull from the control socket
    self._reader_thread = None
    
    # thread to pull from the _event_queue and call handle_event
    self._event_notice = threading.Event()
    self._event_thread = None
    
    # saves our socket's prior _connect() and _close() methods so they can be
    # called along with ours
    
    self._socket_connect = self._socket._connect
    self._socket_close = self._socket._close
    
    self._socket._connect = self._connect
    self._socket._close = self._close
    
    if self._socket.is_alive():
      self._launch_threads()
  
  def msg(self, message):
    """
    Sends a message to our control socket and provides back its reply.
    
    Arguments:
      message (str) - message to be formatted and sent to tor
    
    Returns:
      stem.socket.ControlMessage with the response
    
    Raises:
      stem.socket.ProtocolError the content from the socket is malformed
      stem.socket.SocketError if a problem arises in using the socket
      stem.socket.SocketClosed if the socket is shut down
    """
    
    with self._msg_lock:
      # If our _reply_queue isn't empty then one of a few things happened...
      #
      # - Our connection was closed and probably re-restablished. This was
      #   in reply to pulling for an asynchronous event and getting this is
      #   expected - ignore it.
      #
      # - Pulling for asynchronous events produced an error. If this was a
      #   ProtocolError then it's a tor bug, and if a non-closure SocketError
      #   then it was probably a socket glitch. Deserves an INFO level log
      #   message.
      #
      # - This is a leftover response for a msg() call. We can't tell who an
      #   exception was airmarked for, so we only know that this was the case
      #   if it's a ControlMessage. This should not be possable and indicates
      #   a stem bug. This deserves a NOTICE level log message since it
      #   indicates that one of our callers didn't get their reply.
      
      while not self._reply_queue.empty():
        try:
          response = self._reply_queue.get_nowait()
          
          if isinstance(response, stem.socket.SocketClosed):
            pass # this is fine
          elif isinstance(response, stem.socket.ProtocolError):
            log.info("Tor provided a malformed message (%s)" % response)
          elif isinstance(response, stem.socket.ControllerError):
            log.info("Socket experienced a problem (%s)" % response)
          elif isinstance(response, stem.socket.ControlMessage):
            log.notice("BUG: the msg() function failed to deliver a response: %s" % response)
        except Queue.Empty:
          # the empty() method is documented to not be fully reliable so this
          # isn't entirely surprising
          
          break
      
      self._socket.send(message)
      response = self._reply_queue.get()
      
      # If the message we received back had an exception then re-raise it to the
      # caller. Otherwise return the response.
      
      if isinstance(response, stem.socket.ControllerError):
        raise response
      else:
        return response
  
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
  
  def _handle_event(self, event_message):
    """
    Callback to be overwritten by subclasses for event listening. This is
    notified whenever we receive an event from the control socket.
    
    Arguments:
      event_message (stem.socket.ControlMessage) - message received from the
          control socket
    """
    
    pass
  
  def _connect(self):
    self._launch_threads()
    self._notify_status_listeners(State.INIT, True)
    self._socket_connect()
  
  def _close(self):
    # Our is_alive() state is now false. Our reader thread should already be
    # awake from recv() raising a closure exception. Wake up the event thread
    # too so it can end.
    
    self._event_notice.set()
    
    # joins on our threads if it's safe to do so
    
    for t in (self._reader_thread, self._event_thread):
      if t and t.is_alive() and threading.current_thread() != t:
        t.join()
    
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
    
    # Any changes to our is_alive() state happen under the send lock, so we
    # need to have it to ensure it doesn't change beneath us.
    
    with self._socket._get_send_lock(), self._status_listeners_lock:
      change_timestamp = time.time()
      
      if expect_alive != None and expect_alive != self.is_alive():
        return
      
      for listener, spawn in self._status_listeners:
        if spawn:
          name = "%s notification" % state
          args = (self, state, change_timestamp)
          
          notice_thread = threading.Thread(target = listener, args = args, name = name)
          notice_thread.setDaemon(True)
          notice_thread.start()
        else:
          listener(self, state, change_timestamp)
  
  def _launch_threads(self):
    """
    Initializes daemon threads. Threads can't be reused so we need to recreate
    them if we're restarted.
    """
    
    # In theory concurrent calls could result in multple start() calls on a
    # single thread, which would cause an unexpeceted exception. Best be safe.
    
    with self._socket._get_send_lock():
      if not self._reader_thread or not self._reader_thread.is_alive():
        self._reader_thread = threading.Thread(target = self._reader_loop, name = "Tor Listener")
        self._reader_thread.setDaemon(True)
        self._reader_thread.start()
      
      if not self._event_thread or not self._event_thread.is_alive():
        self._event_thread = threading.Thread(target = self._event_loop, name = "Event Notifier")
        self._event_thread.setDaemon(True)
        self._event_thread.start()
  
  def _reader_loop(self):
    """
    Continually pulls from the control socket, directing the messages into
    queues based on their type. Controller messages come in two varieties...
    
    - Responses to messages we've sent (GETINFO, SETCONF, etc).
    - Asynchronous events, identified by a status code of 650.
    """
    
    while self.is_alive():
      try:
        control_message = self._socket.recv()
        
        if control_message.content()[-1][0] == "650":
          # asynchronous message, adds to the event queue and wakes up its handler
          self._event_queue.put(control_message)
          self._event_notice.set()
        else:
          # response to a msg() call
          self._reply_queue.put(control_message)
      except stem.socket.ControllerError, exc:
        # Assume that all exceptions belong to the reader. This isn't always
        # true, but the msg() call can do a better job of sorting it out.
        #
        # Be aware that the msg() method relies on this to unblock callers.
        
        self._reply_queue.put(exc)
  
  def _event_loop(self):
    """
    Continually pulls messages from the _event_queue and sends them to our
    handle_event callback. This is done via its own thread so subclasses with a
    lengthy handle_event implementation don't block further reading from the
    socket.
    """
    
    while self.is_alive():
      try:
        event_message = self._event_queue.get_nowait()
        self._handle_event(event_message)
      except Queue.Empty:
        self._event_notice.wait()
        self._event_notice.clear()

