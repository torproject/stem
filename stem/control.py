# The following is very much a work in progress and mostly scratch (I just
# wanted to make sure other work would nicely do the async event handling).

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
      event_message (stem.socket.ControlMessage) -
          message received from the control socket
    """
    
    pass
  
  def send(self, message):
    """
    Sends a message to the control socket and waits for a reply.
    
    Arguments:
      message (str) - message to be sent to the control socket
    
    Returns:
      stem.socket.ControlMessage with the response from the control socket
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
        # TODO: this raises a SocketClosed when... well, the socket is closed
        control_message = stem.socket.recv_message(self._control_socket_file)
        
        if control_message.content()[-1][0] == "650":
          # adds this to the event queue and wakes up the handler
          
          self._event_cond.acquire()
          self._event_queue.put(control_message)
          self._event_cond.notifyAll()
          self._event_cond.release()
        else:
          # TODO: figure out a good method for terminating the socket thread
          self._reply_queue.put(control_message)
      except stem.socket.ProtocolError, exc:
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


