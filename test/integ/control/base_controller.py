"""
Integration tests for the stem.control.BaseController class.
"""

import unittest

import stem.control
import test.runner
import test.mocking as mocking
import test.integ.socket.control_socket

class TestBaseController(unittest.TestCase):
  def setUp(self):
    test.runner.require_control(self)
  
  def tearDown(self):
    mocking.revert_mocking()
  
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

