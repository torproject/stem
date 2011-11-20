"""
Integration tests for the stem.util.conf class and functions.
"""

import os
import tempfile
import unittest

import stem.util.conf

CONF_PATH = tempfile.mktemp("-conf-test")
CONF_HEADER = """# Demo configuration for integration tests to run against. Nothing to see here,
# move along, move along.
"""

EXAMPLE_CONF = """%s
destination.ip 1.2.3.4
destination.port blarg

startup.run export PATH=$PATH:~/bin
startup.run alias l=ls
""" % CONF_HEADER

class TestConf(unittest.TestCase):
  """
  Tests the stem.util.conf contents.
  """
  
  def tearDown(self):
    # cleans up test configurations we made
    if os.path.exists(CONF_PATH):
      os.remove(CONF_PATH)
  
  def test_example(self):
    """
    Checks that the pydoc example is correct.
    """
    
    test_conf_file = open(CONF_PATH, "w")
    test_conf_file.write(EXAMPLE_CONF)
    test_conf_file.close()
    
    ssh_config = {"login.user": "atagar",
                  "login.password": "pepperjack_is_awesome!",
                  "destination.ip": "127.0.0.1",
                  "destination.port": 22,
                  "startup.run": []}
    
    user_config = stem.util.conf.get_config("integ-ssh_login")
    user_config.load(CONF_PATH)
    user_config.update(ssh_config)
    
    self.assertEquals("atagar", ssh_config["login.user"])
    self.assertEquals("pepperjack_is_awesome!", ssh_config["login.password"])
    self.assertEquals("1.2.3.4", ssh_config["destination.ip"])
    self.assertEquals(22, ssh_config["destination.port"])
    self.assertEquals(["export PATH=$PATH:~/bin", "alias l=ls"], ssh_config["startup.run"])
    
    user_config.clear()

