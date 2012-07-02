"""
Unit tests for the stem.exit_policy.ExitPolicy parsing and class.
"""

import unittest
import stem.exit_policy
import stem.util.system

import test.mocking as mocking

class TestExitPolicy(unittest.TestCase):
  def tearDown(self):
    pass
  
  def test_parsing(self):
    """
    Tests parsing by the ExitPolicy class constructor.
    """
    
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies.add("accept *:80")
    exit_policies.add("accept *:443")
    exit_policies.add("reject *:*")
    self.assertEqual(str(exit_policies), "accept *:80, accept *:443, reject *:*")
    
    exit_policies = stem.exit_policy.ExitPolicy()
    
    # check ip address
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept 256.255.255.255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept -10.255.255.255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept 255.-10.255.255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept 255.255.-10.255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept -255.255.255.-10:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept a.b.c.d:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept 255.255.255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept -255.255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept 255:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept -:80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept :80")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept ...:80")
    
    # check input string
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "foo 255.255.255.255:80")
    
    # check ports
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:0001")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:0")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:-1")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:+1")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:+1-1")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:a")
    self.assertRaises(stem.exit_policy.ExitPolicyError, exit_policies.add, "accept *:70000")
    
  def test_check(self):
    """
    Tests if exiting to this ip is allowed.
    """
    
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies.add("accept *:80")
    exit_policies.add("accept *:443")
    exit_policies.add("reject *:*")
    
    self.assertTrue(exit_policies.check("www.google.com", 80))
    self.assertTrue(exit_policies.check("www.atagar.com", 443))
    
    self.assertFalse(exit_policies.check("www.atagar.com", 22))
    self.assertFalse(exit_policies.check("www.atagar.com", 8118))
    
  def test_is_exiting_allowed(self):
    """
    Tests if this is an exit node
    """
    
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies.add("accept *:80")
    exit_policies.add("accept *:443")
    exit_policies.add("reject *:*")
    
    self.assertTrue(exit_policies.is_exiting_allowed())
    
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies = stem.exit_policy.ExitPolicy()
    exit_policies.add("reject *:*")
    
    self.assertFalse(exit_policies.is_exiting_allowed())
    
  def test_microdesc_exit_parsing(self):
    microdesc_exit_policy = stem.exit_policy.MicrodescriptorExitPolicy("accept 80,443")
    
    self.assertEqual(str(microdesc_exit_policy),"accept 80,443")
    
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "accept 80,-443")
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "accept 80,+443")
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "accept 80,66666")
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "reject 80,foo")
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "bar 80,foo")
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "foo")
    self.assertRaises(stem.exit_policy.ExitPolicyError, stem.exit_policy.MicrodescriptorExitPolicy, "bar 80-foo")
    
  def test_micodesc_exit_check(self):
    microdesc_exit_policy = stem.exit_policy.MicrodescriptorExitPolicy("accept 80,443")
    
    self.assertTrue(microdesc_exit_policy.check(80))
    self.assertTrue(microdesc_exit_policy.check("www.atagar.com", 443))
    
    self.assertFalse(microdesc_exit_policy.check(22))
    self.assertFalse(microdesc_exit_policy.check("www.atagar.com", 8118))
