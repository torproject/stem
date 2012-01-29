"""
Integration tests for the connect_* convenience functions.
"""

import sys
import unittest
import StringIO

import stem.connection
import test.runner

class TestConnect(unittest.TestCase):
  def setUp(self):
    test.runner.require_control(self)
    
    # prevents the function from printing to the real stdout
    self.original_stdout = sys.stdout
    sys.stdout = StringIO.StringIO()
  
  def tearDown(self):
    sys.stdout = self.original_stdout
  
  def test_connect_port(self):
    """
    Basic sanity checks for the connect_port function.
    """
    
    control_socket = stem.connection.connect_port(
      control_port = test.runner.CONTROL_PORT,
      password = test.runner.CONTROL_PASSWORD,
      controller = stem.connection.Controller.NONE)
    
    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      test.runner.exercise_socket(self, control_socket)
      control_socket.close()
    else:
      self.assertEquals(control_socket, None)
  
  def test_connect_socket_file(self):
    """
    Basic sanity checks for the connect_socket_file function.
    """
    
    control_socket = stem.connection.connect_socket_file(
      socket_path = test.runner.CONTROL_SOCKET_PATH,
      password = test.runner.CONTROL_PASSWORD,
      controller = stem.connection.Controller.NONE)
    
    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      test.runner.exercise_socket(self, control_socket)
      control_socket.close()
    else:
      self.assertEquals(control_socket, None)

