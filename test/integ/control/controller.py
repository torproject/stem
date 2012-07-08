"""
Integration tests for the stem.control.Controller class.
"""

from __future__ import with_statement

import unittest
import tempfile
import shutil

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
  
  def test_getconf(self):
    """
    Exercises GETCONF with valid and invalid queries.
    """
    
    if test.runner.require_control(self): return
    
    runner = test.runner.get_runner()
    
    with runner.get_tor_controller() as controller:
      socket = controller.get_socket()
      if isinstance(socket, stem.socket.ControlPort):
        connection_value = str(socket.get_port())
        config_key = "ControlPort"
      elif isinstance(socket, stem.socket.ControlSocketFile):
        connection_value = str(socket.get_socket_path())
        config_key = "ControlSocket"
      
      # successful single query
      self.assertEqual(connection_value, controller.get_conf(config_key))
      self.assertEqual(connection_value, controller.get_conf(config_key, "la-di-dah"))
      
      # succeessful batch query
      expected = {config_key: [connection_value]}
      self.assertEqual(expected, controller.get_conf_map([config_key]))
      self.assertEqual(expected, controller.get_conf_map([config_key], "la-di-dah"))
      
      request_params = ["ControlPORT", "dirport", "datadirectory"]
      reply_params = controller.get_conf_map(request_params, multiple=False).keys()
      self.assertEqual(set(request_params), set(reply_params))
      
      # non-existant option(s)
      self.assertRaises(stem.socket.InvalidArguments, controller.get_conf, "blarg")
      self.assertEqual("la-di-dah", controller.get_conf("blarg", "la-di-dah"))
      self.assertRaises(stem.socket.InvalidArguments, controller.get_conf_map, "blarg")
      self.assertEqual("la-di-dah", controller.get_conf_map("blarg", "la-di-dah"))
      
      self.assertRaises(stem.socket.InvalidRequest, controller.get_conf_map, ["blarg", "huadf"], multiple = True)
      self.assertEqual("la-di-dah", controller.get_conf_map(["erfusdj", "afiafj"], "la-di-dah", multiple = True))
      
      # multivalue configuration keys
      nodefamilies = [("abc", "xyz", "pqrs"), ("mno", "tuv", "wxyz")]
      controller.msg("SETCONF %s" % " ".join(["nodefamily=\"" + ",".join(x) + "\"" for x in nodefamilies]))
      self.assertEqual([",".join(n) for n in nodefamilies], controller.get_conf("nodefamily", multiple = True))
      controller.msg("RESETCONF NodeFamily")
      
      # empty input
      self.assertEqual(None, controller.get_conf(""))
      self.assertEqual({}, controller.get_conf_map([]))
      self.assertEqual({}, controller.get_conf_map([""]))
      self.assertEqual(None, controller.get_conf("          "))
      self.assertEqual({}, controller.get_conf_map(["    ", "        "]))
      
      self.assertEqual("la-di-dah", controller.get_conf("", "la-di-dah"))
      self.assertEqual({}, controller.get_conf_map("", "la-di-dah"))
      self.assertEqual({}, controller.get_conf_map([], "la-di-dah"))
  
  def test_set_options(self):
    """
    Exercises set_option() and set_options() with valid and invalid requests.
    """
    
    if test.runner.require_control(self): return
    
    runner = test.runner.get_runner()
    tmpdir = tempfile.mkdtemp()
    
    with runner.get_tor_controller() as controller:
      try:
        # successfully set a single option
        connlimit = int(controller.get_conf("ConnLimit"))
        controller.set_option("connlimit", str(connlimit - 1))
        self.assertEqual(connlimit - 1, int(controller.get_conf("ConnLimit")))
        
        # successfully set a single list option
        exit_policy = ["accept *:7777", "reject *:*"]
        controller.set_option("ExitPolicy", exit_policy)
        self.assertEqual(exit_policy, controller.get_conf("ExitPolicy", multiple = True))
        
        # fail to set a single option
        try:
          controller.set_option("invalidkeyboo", "abcde")
          self.fail()
        except stem.socket.InvalidArguments, exc:
          self.assertEqual(["invalidkeyboo"], exc.arguments)
        
        # successfully sets multiple config options
        controller.set_options({
          "connlimit": str(connlimit - 2),
          "contactinfo": "stem@testing",
        })
        
        self.assertEqual(connlimit - 2, int(controller.get_conf("ConnLimit")))
        self.assertEqual("stem@testing", controller.get_conf("contactinfo"))
        
        # fail to set multiple config options
        try:
          controller.set_options({
            "contactinfo": "stem@testing",
            "bombay": "vadapav",
          })
          self.fail()
        except stem.socket.InvalidArguments, exc:
          self.assertEqual(["bombay"], exc.arguments)
        
        # context-sensitive keys (the only retched things for which order matters)
        controller.set_options((
          ("HiddenServiceDir", tmpdir),
          ("HiddenServicePort", "17234 127.0.0.1:17235"),
        ))
        
        self.assertEqual(tmpdir, controller.get_conf("HiddenServiceDir"))
        self.assertEqual("17234 127.0.0.1:17235", controller.get_conf("HiddenServicePort"))
      finally:
        # reverts configuration changes
        controller.set_options((
          ("ExitPolicy", "reject *:*"),
          ("ConnLimit", None),
          ("ContactInfo", None),
          ("HiddenServiceDir", None),
          ("HiddenServicePort", None),
        ), reset = True)
        
        shutil.rmtree(tmpdir)

