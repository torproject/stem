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
    # none of these tests apply if there's no control connection
    if not test.runner.get_runner().is_accessible():
      self.skipTest("(no connection)")
  
  def test_connect_port(self):
    """
    Basic sanity checks for the connect_port function.
    """
    
    self._test_connect(True)
  
  def test_connect_socket_file(self):
    """
    Basic sanity checks for the connect_socket_file function.
    """
    
    self._test_connect(False)
  
  def _test_connect(self, is_port):
    """
    Common implementations for the test_connect_* functions.
    """
    
    # prevents the function from printing to the real stdout
    original_stdout = sys.stdout
    sys.stdout = StringIO.StringIO()
    
    try:
      ctl_pw = test.runner.CONTROL_PASSWORD
      controller = stem.connection.Controller.NONE
      
      if is_port:
        opt_type = test.runner.Torrc.PORT
        ctl_port = test.runner.CONTROL_PORT
        control_socket = stem.connection.connect_port(control_port = ctl_port, password = ctl_pw, controller = controller)
      else:
        opt_type = test.runner.Torrc.SOCKET
        ctl_socket = test.runner.CONTROL_SOCKET_PATH
        control_socket = stem.connection.connect_socket_file(socket_path = ctl_socket, password = ctl_pw, controller = controller)
      
      if opt_type in test.runner.get_runner().get_options():
        test.runner.exercise_socket(self, control_socket)
        control_socket.close()
      else:
        self.assertEquals(control_socket, None)
    finally:
      sys.stdout = original_stdout

