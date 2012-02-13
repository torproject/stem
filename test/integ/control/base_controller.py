"""
Integration tests for the stem.control.BaseController class.
"""

import time
import unittest

import stem.control
import stem.socket
import test.runner
import test.mocking as mocking

class StateObserver:
  """
  Simple container for listening to ControlSocket state changes and
  rembembering them for the test.
  """
  
  controller = None
  state = None
  timestamp = None
  
  def reset(self):
    self.controller = None
    self.state = None
    self.timestamp = None
  
  def listener(self, controller, state, timestamp):
    self.controller = controller
    self.state = state
    self.timestamp = timestamp

class TestBaseController(unittest.TestCase):
  def setUp(self):
    test.runner.require_control(self)
  
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_from_port(self):
    """
    Basic sanity check for the from_port constructor.
    """
    
    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      controller = stem.control.BaseController.from_port(control_port = test.runner.CONTROL_PORT)
      self.assertTrue(isinstance(controller, stem.control.BaseController))
    else:
      self.assertRaises(stem.socket.SocketError, stem.control.BaseController.from_port, "127.0.0.1", test.runner.CONTROL_PORT)
  
  def test_from_socket_file(self):
    """
    Basic sanity check for the from_socket_file constructor.
    """
    
    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      controller = stem.control.BaseController.from_socket_file(test.runner.CONTROL_SOCKET_PATH)
      self.assertTrue(isinstance(controller, stem.control.BaseController))
    else:
      self.assertRaises(stem.socket.SocketError, stem.control.BaseController.from_socket_file, test.runner.CONTROL_SOCKET_PATH)
  
  def test_status_notifications(self):
    """
    Checks basic functionality of the add_status_listener() and
    remove_status_listener() methods.
    """
    
    state_observer = StateObserver()
    
    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      controller = stem.control.BaseController(control_socket)
      controller.add_status_listener(state_observer.listener, False)
      
      control_socket.close()
      self.assertEquals(controller, state_observer.controller)
      self.assertEquals(stem.control.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
      
      control_socket.connect()
      self.assertEquals(controller, state_observer.controller)
      self.assertEquals(stem.control.State.INIT, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
      
      # cause the socket to shut down without calling close()
      control_socket.send("Blarg!")
      control_socket.recv()
      self.assertRaises(stem.socket.SocketClosed, control_socket.recv)
      self.assertEquals(controller, state_observer.controller)
      self.assertEquals(stem.control.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
      
      # remove listener and make sure we don't get further notices
      controller.remove_status_listener(state_observer.listener)
      control_socket.connect()
      self.assertEquals(None, state_observer.controller)
      self.assertEquals(None, state_observer.state)
      self.assertEquals(None, state_observer.timestamp)
      state_observer.reset()
      
      # add with spawn as true, we need a little delay on this since we then
      # get the notice asynchronously
      
      controller.add_status_listener(state_observer.listener, True)
      control_socket.close()
      time.sleep(0.1) # not much work going on so this doesn't need to be much
      self.assertEquals(controller, state_observer.controller)
      self.assertEquals(stem.control.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp < time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()

