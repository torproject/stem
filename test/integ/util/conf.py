"""
Integration tests for the stem.util.conf class and functions.
"""

import os
import unittest

import stem.util.conf
import test.runner

CONF_HEADER = """# Demo configuration for integration tests to run against. Nothing to see here,
# move along, move along.
"""

EXAMPLE_CONF = """
destination.ip 1.2.3.4
destination.port blarg

startup.run export PATH=$PATH:~/bin
startup.run alias l=ls
"""

MULTILINE_CONF = """
multiline.entry.simple
|la de da
|and a ho hum

multiline.entry.leading_whitespace
 |la de da
     |and a ho hum

multiline.entry.empty

multiline.entry.squashed_top
|la de da
|and a ho hum
multiline.entry.squashed_bottom
|la de da
|and a ho hum
"""

def _get_test_config_path():
  return os.path.join(test.runner.get_runner().get_test_dir(), "integ_test_cfg")

def _make_config(contents):
  """
  Writes a test configuration to disk, returning the path where it is located.
  """
  
  test_config_path = _get_test_config_path()
  
  test_conf_file = open(test_config_path, "w")
  test_conf_file.write(CONF_HEADER)
  test_conf_file.write(contents)
  test_conf_file.close()
  
  return test_config_path

class TestConf(unittest.TestCase):
  def tearDown(self):
    # clears the config contents
    test_config = stem.util.conf.get_config("integ_testing")
    test_config.clear()
    test_config.clear_listeners()
    
    # cleans up test configurations we made
    test_config_path = _get_test_config_path()
    
    if os.path.exists(test_config_path):
      os.remove(test_config_path)
  
  def test_example(self):
    """
    Checks that the pydoc example is correct.
    """
    
    ssh_config = {"login.user": "atagar",
                  "login.password": "pepperjack_is_awesome!",
                  "destination.ip": "127.0.0.1",
                  "destination.port": 22,
                  "startup.run": []}
    
    test_config_path = _make_config(EXAMPLE_CONF)
    user_config = stem.util.conf.get_config("integ_testing")
    user_config.load(test_config_path)
    user_config.synchronize(ssh_config)
    
    self.assertEquals("atagar", ssh_config["login.user"])
    self.assertEquals("pepperjack_is_awesome!", ssh_config["login.password"])
    self.assertEquals("1.2.3.4", ssh_config["destination.ip"])
    self.assertEquals(22, ssh_config["destination.port"])
    self.assertEquals(["export PATH=$PATH:~/bin", "alias l=ls"], ssh_config["startup.run"])
  
  def test_load_multiline(self):
    """
    Tests the load method with multi-line configuration files.
    """
    
    test_config_path = _make_config(MULTILINE_CONF)
    test_config = stem.util.conf.get_config("integ_testing")
    test_config.load(test_config_path)
        
    for entry in ("simple", "leading_whitespace", "squashed_top", "squashed_bottom"):
      self.assertEquals("la de da\nand a ho hum", test_config.get("multiline.entry.%s" % entry))
    
    self.assertEquals("", test_config.get("multiline.entry.empty"))

  def test_save_multiline(self):
    """
    Tests the save method with multi-line configuration files.
    """

    test_config_path = _make_config(MULTILINE_CONF)
    test_config = stem.util.conf.get_config("integ_testing")
    test_config.load(test_config_path)

    test_config.save()
    test_config.clear()

    test_config = stem.util.conf.get_config("integ_testing")
    test_config.load(test_config_path)

    for entry in ("simple", "leading_whitespace", "squashed_top", "squashed_bottom"):
      self.assertEquals("la de da\nand a ho hum", test_config.get("multiline.entry.%s" % entry))
    
    self.assertEquals("", test_config.get("multiline.entry.empty"))

  def test_save_singleline(self):
    """
    Tests the save method with mingle-line configuration files.
    """
    ssh_config = {"login.user": "atagar",
                  "login.password": "pepperjack_is_awesome!",
                  "destination.ip": "127.0.0.1",
                  "destination.port": 22,
                  "startup.run": []}
    
    test_config_path = _make_config(EXAMPLE_CONF)
    user_config = stem.util.conf.get_config("integ_testing")
    user_config.load(test_config_path)
        
    user_config.set("destination.port", '22')
    user_config.set("destination.ip", "127.0.0.1")

    user_config.save()
    user_config.clear()
    user_config.load(test_config_path)

    self.assertEquals('22', user_config.get("destination.port"))
    self.assertEquals("127.0.0.1", user_config.get("destination.ip"))
