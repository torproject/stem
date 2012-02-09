"""
Integration tests for the stem.socket.ControlSocket subclasses. When ran these
test basic functionality for a ControlPort *or* ControlSocketFile, depending on
which can connect to our tor instance.

These tests share a similar domain with those for the ControlMessage, but where
those focus on parsing and correctness of the content these are more concerned
with the behavior of the socket itself.
"""

import time
import unittest

import stem.connection
import stem.control
import stem.socket
import test.runner

class StateObserver:
  """
  Simple container for listening to ControlSocket state changes and
  rembembering them for the test.
  """
  
  control_socket = None
  state = None
  timestamp = None
  
  def reset(self):
    self.control_socket = None
    self.state = None
    self.timestamp = None
  
  def listener(self, control_socket, state, timestamp):
    self.control_socket = control_socket
    self.state = state
    self.timestamp = timestamp

class TestControlSocket(unittest.TestCase):
  def setUp(self):
    test.runner.require_control(self)
  
  def test_send_buffered(self):
    """
    Sends multiple requests before receiving back any of the replies.
    """
    
    runner = test.runner.get_runner()
    tor_version = runner.get_tor_version()
    
    with runner.get_tor_socket() as control_socket:
      for i in range(100):
        control_socket.send("GETINFO version")
      
      for i in range(100):
        response = control_socket.recv()
        self.assertEquals("version=%s\nOK" % tor_version, str(response))
  
  def test_send_closed(self):
    """
    Sends a message after we've closed the connection.
    """
    
    with test.runner.get_runner().get_tor_socket() as control_socket:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      self.assertFalse(control_socket.is_alive())
      
      self.assertRaises(stem.socket.SocketClosed, control_socket.send, "blarg")
  
  def test_send_disconnected(self):
    """
    Sends a message to a socket that has been disconnected by the other end.
    
    Our behavior upon disconnection slightly differs based on if we're a port
    or socket file based connection. With a control port we won't notice the
    disconnect (is_alive() will return True) until we've made a failed recv()
    call. With a file socket, however, we'll also fail when calling send().
    """
    
    with test.runner.get_runner().get_tor_socket() as control_socket:
      control_socket.send("QUIT")
      self.assertEquals("closing connection", str(control_socket.recv()))
      self.assertTrue(control_socket.is_alive())
      
      # If we send another message to a port based socket then it will seem to
      # succeed. However, a file based socket should report a failure.
      
      if control_socket.get_socket().__class__ == stem.socket.ControlPort:
        control_socket.send("blarg")
        self.assertTrue(control_socket.is_alive())
      else:
        self.assertRaises(stem.socket.SocketClosed, control_socket.send, "blarg")
        self.assertFalse(control_socket.is_alive())
  
  def test_recv_closed(self):
    """
    Receives a message after we've closed the connection.
    """
    
    with test.runner.get_runner().get_tor_socket() as control_socket:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      self.assertFalse(control_socket.is_alive())
      
      self.assertRaises(stem.socket.SocketClosed, control_socket.recv)
  
  def test_recv_disconnected(self):
    """
    Receives a message from a socket that has been disconnected by the other
    end.
    """
    
    with test.runner.get_runner().get_tor_socket() as control_socket:
      control_socket.send("QUIT")
      self.assertEquals("closing connection", str(control_socket.recv()))
      
      # Neither a port or file based socket will know that tor has hung up on
      # the connection at this point. We should know after calling recv(),
      # however.
      
      self.assertTrue(control_socket.is_alive())
      self.assertRaises(stem.socket.SocketClosed, control_socket.recv)
      self.assertFalse(control_socket.is_alive())
  
  def test_connect_repeatedly(self):
    """
    Checks that we can reconnect, use, and disconnect a socket repeatedly.
    """
    
    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      for i in range(10):
        # this will raise if the PROTOCOLINFO query fails
        stem.connection.get_protocolinfo(control_socket)
        
        control_socket.close()
        self.assertRaises(stem.socket.SocketClosed, control_socket.send, "PROTOCOLINFO 1")
        control_socket.connect()
  
  def test_status_notifications(self):
    """
    Checks basic functionality of the add_status_listener() and
    remove_status_listener() methods.
    """
    
    state_observer = StateObserver()
    
    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      control_socket.add_status_listener(state_observer.listener, False)
      
      control_socket.close()
      self.assertEquals(control_socket, state_observer.control_socket)
      self.assertEquals(stem.socket.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
      
      control_socket.connect()
      self.assertEquals(control_socket, state_observer.control_socket)
      self.assertEquals(stem.socket.State.INIT, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
      
      # cause the socket to shut down without calling close()
      control_socket.send("Blarg!")
      control_socket.recv()
      self.assertRaises(stem.socket.SocketClosed, control_socket.recv)
      self.assertEquals(control_socket, state_observer.control_socket)
      self.assertEquals(stem.socket.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
      
      # remove listener and make sure we don't get further notices
      control_socket.remove_status_listener(state_observer.listener)
      control_socket.connect()
      self.assertEquals(None, state_observer.control_socket)
      self.assertEquals(None, state_observer.state)
      self.assertEquals(None, state_observer.timestamp)
      state_observer.reset()
      
      # add with spawn as true, we need a little delay on this since we then
      # get the notice asynchronously
      
      control_socket.add_status_listener(state_observer.listener, True)
      control_socket.close()
      time.sleep(0.1) # not much work going on so this doesn't need to be much
      self.assertEquals(control_socket, state_observer.control_socket)
      self.assertEquals(stem.socket.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()

