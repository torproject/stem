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
  
  def test_getinfo(self):
    """
    Exercises GETINFO with valid and invalid queries.
    """
    
    runner = test.runner.get_runner()
    
    with runner.get_tor_controller() as controller:
      # successful single query
      
      torrc_path = runner.get_torrc_path()
      self.assertEqual(torrc_path, controller.get_info("config-file"))
      self.assertEqual(torrc_path, controller.get_info("config-file", "ho hum"))
      
      expected = {"config-file": torrc_path}
      self.assertEqual(expected, controller.get_info(["config-file"]))
      self.assertEqual(expected, controller.get_info(["config-file"], "ho hum"))
      
      # successful batch query, we don't know the values so just checking for
      # the keys
      
      getinfo_params = set(["version", "config-file", "config/names"])
      self.assertEqual(getinfo_params, set(controller.get_info(["version", "config-file", "config/names"]).keys()))
      
      # non-existant option
      
      self.assertRaises(stem.socket.ControllerError, controller.get_info, "blarg")
      self.assertEqual("ho hum", controller.get_info("blarg", "ho hum"))
      
      # empty input
      
      self.assertRaises(stem.socket.ControllerError, controller.get_info, "")
      self.assertEqual("ho hum", controller.get_info("", "ho hum"))
      
      self.assertEqual({}, controller.get_info([]))
      self.assertEqual({}, controller.get_info([], {}))

