"""
Integration tests for the stem.control.Controller class.
"""

from __future__ import with_statement

import unittest

import stem.control
import stem.socket
import stem.version
import stem.response.protocolinfo
import test.runner

class TestController(unittest.TestCase):
  def test_from_port(self):
    """
    Basic sanity check for the from_port constructor.
    """
    
    if test.runner.require_control(self): return
    
    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      with stem.control.Controller.from_port(control_port = test.runner.CONTROL_PORT) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      self.assertRaises(stem.socket.SocketError, stem.control.Controller.from_port, "127.0.0.1", test.runner.CONTROL_PORT)
  
  def test_from_socket_file(self):
    """
    Basic sanity check for the from_socket_file constructor.
    """
    
    if test.runner.require_control(self): return
    
    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      with stem.control.Controller.from_socket_file(socket_path = test.runner.CONTROL_SOCKET_PATH) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      self.assertRaises(stem.socket.SocketError, stem.control.Controller.from_socket_file, test.runner.CONTROL_SOCKET_PATH)
  
  def test_getinfo(self):
    """
    Exercises GETINFO with valid and invalid queries.
    """
    
    if test.runner.require_control(self): return
    
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
  
  def test_get_version(self):
    """
    Test that the convenient method get_version() works.
    """
    
    if test.runner.require_control(self): return
    
    runner = test.runner.get_runner()
    with runner.get_tor_controller() as controller:
      version = controller.get_version()
      self.assertTrue(isinstance(version, stem.version.Version))
      self.assertEqual(version, runner.get_tor_version())
  
  def test_authenticate(self):
    """
    Test that the convenient method authenticate() works.
    """
    
    if test.runner.require_control(self): return
    
    runner = test.runner.get_runner()
    with runner.get_tor_controller(False) as controller:
      controller.authenticate(test.runner.CONTROL_PASSWORD)
      test.runner.exercise_controller(self, controller)
  
  def test_protocolinfo(self):
    """
    Test that the convenient method protocolinfo() works.
    """
    
    if test.runner.require_control(self): return
    
    runner = test.runner.get_runner()
    
    with runner.get_tor_controller(False) as controller:
      protocolinfo = controller.protocolinfo()
      self.assertTrue(isinstance(protocolinfo, stem.response.protocolinfo.ProtocolInfoResponse))
      
      # Doing a sanity test on the ProtocolInfoResponse instance returned.
      tor_options = runner.get_options()
      tor_version = runner.get_tor_version()
      auth_methods = []
      
      if test.runner.Torrc.COOKIE in tor_options:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.COOKIE)
        
        if tor_version.meets_requirements(stem.version.Requirement.AUTH_SAFECOOKIE):
          auth_methods.append(stem.response.protocolinfo.AuthMethod.SAFECOOKIE)
      
      if test.runner.Torrc.PASSWORD in tor_options:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.PASSWORD)
      
      if not auth_methods:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.NONE)
      
      self.assertEqual(tuple(auth_methods), protocolinfo.auth_methods)

