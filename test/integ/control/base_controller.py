"""
Integration tests for the stem.control.BaseController class.
"""

import unittest

import stem.control
import stem.socket
import test.runner
import test.mocking as mocking
import test.integ.socket.control_socket

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
  
  def test_socket_passthrough(self):
    """
    The BaseController is a passthrough for the socket it is built from, so
    runs the ControlSocket integ tests again against it.
    """
    
    # overwrites the Runner's get_tor_socket() to provide back a ControlSocket
    # wrapped by a BaseContorller
    
    def mock_get_tor_socket(self, authenticate = True):
      real_get_tor_socket = mocking.get_real_function(test.runner.Runner.get_tor_socket)
      control_socket = real_get_tor_socket(self, authenticate)
      return stem.control.BaseController(control_socket)
    
    mocking.mock_method(test.runner.Runner, "get_tor_socket", mock_get_tor_socket)
    
    # sanity check that the mocking is working
    example_socket = test.runner.get_runner().get_tor_socket()
    self.assertTrue(isinstance(example_socket, stem.control.BaseController))
    
    # re-runs all of the control_socket tests
    socket_test_class = test.integ.socket.control_socket.TestControlSocket
    for method in socket_test_class.__dict__:
      if method.startswith("test_"):
        socket_test_class.__dict__[method](self)

