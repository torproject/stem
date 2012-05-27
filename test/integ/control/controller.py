"""
Integration tests for the stem.control.Controller class.
"""

import unittest

import stem.control
import stem.socket
import test.runner

class TestController(unittest.TestCase):
  def setUp(self):
    test.runner.require_control(self)
  
  def test_from_port(self):
    """
    Basic sanity check for the from_port constructor.
    """
    
    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      with stem.control.Controller.from_port(control_port = test.runner.CONTROL_PORT) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      self.assertRaises(stem.socket.SocketError, stem.control.Controller.from_port, "127.0.0.1", test.runner.CONTROL_PORT)
  
  def test_from_socket_file(self):
    """
    Basic sanity check for the from_socket_file constructor.
    """
    
    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      with stem.control.Controller.from_socket_file(socket_path = test.runner.CONTROL_SOCKET_PATH) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      self.assertRaises(stem.socket.SocketError, stem.control.Controller.from_socket_file, test.runner.CONTROL_SOCKET_PATH)

