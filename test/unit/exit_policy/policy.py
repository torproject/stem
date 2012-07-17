"""
Unit tests for the stem.exit_policy.ExitPolicy class.
"""

import unittest
import stem.exit_policy
import stem.util.system
from stem.exit_policy import ExitPolicy, ExitPolicyRule

import test.mocking as mocking

class TestExitPolicy(unittest.TestCase):
  def test_example(self):
    # tests the ExitPolicy and MicrodescriptorExitPolicy pydoc examples
    policy = ExitPolicy("accept *:80", "accept *:443", "reject *:*")
    self.assertEquals("accept *:80, accept *:443, reject *:*", str(policy))
    self.assertEquals("accept 80, 443", policy.summary())
    self.assertTrue(policy.can_exit_to("75.119.206.243", 80))
    
    # TODO: add MicrodescriptorExitPolicy after it has been revised
  
  def test_constructor(self):
    # The ExitPolicy constructor takes a series of string or ExitPolicyRule
    # entries. Extra whitespace is ignored to make csvs easier to handle.
    
    expected_policy = ExitPolicy(
      ExitPolicyRule('accept *:80'),
      ExitPolicyRule('accept *:443'),
      ExitPolicyRule('reject *:*'),
    )
    
    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    self.assertEquals(expected_policy, policy)
    
    policy = ExitPolicy(*"accept *:80, accept *:443, reject *:*".split(","))
    self.assertEquals(expected_policy, policy)
  
  def test_set_default_allowed(self):
    policy = ExitPolicy('reject *:80', 'accept *:443')
    
    # our default for being allowed defaults to True
    self.assertFalse(policy.can_exit_to("75.119.206.243", 80))
    self.assertTrue(policy.can_exit_to("75.119.206.243", 443))
    self.assertTrue(policy.can_exit_to("75.119.206.243", 999))
    
    policy.set_default_allowed(False)
    self.assertFalse(policy.can_exit_to("75.119.206.243", 80))
    self.assertTrue(policy.can_exit_to("75.119.206.243", 443))
    self.assertFalse(policy.can_exit_to("75.119.206.243", 999))
    
    # Our is_exiting_allowed() is also influcenced by this flag if we lack any
    # 'accept' rules.
    
    policy = ExitPolicy()
    self.assertTrue(policy.is_exiting_allowed())
    
    policy.set_default_allowed(False)
    self.assertFalse(policy.is_exiting_allowed())
  
  def test_can_exit_to(self):
    # Basic sanity test for our can_exit_to() method. Most of the interesting
    # use cases (ip masks, wildcards, etc) are covered by the ExitPolicyRule
    # tests.
    
    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    
    for i in xrange(1, 500):
      ip_addr = "%i.%i.%i.%i" % (i / 2, i / 2, i / 2, i / 2)
      expected_result = i in (80, 443)
      
      self.assertEquals(expected_result, policy.can_exit_to(ip_addr, i))
      self.assertEquals(expected_result, policy.can_exit_to(port = i))
  
  def test_is_exiting_allowed(self):
    test_inputs = {
      (): True,
      ('accept *:*', ): True,
      ('reject *:*', ): False,
      ('accept *:80', 'reject *:*'): True,
      ('reject *:80', 'accept *:80', 'reject *:*'): False,
      ('reject *:50-90', 'accept *:80', 'reject *:*'): False,
      ('reject *:2-65535', 'accept *:80-65535', 'reject *:*'): False,
      ('reject *:2-65535', 'accept 127.0.0.0:1', 'reject *:*'): True,
      ('reject 127.0.0.1:*', 'accept *:80', 'reject *:*'): True,
    }
    
    for rules, expected_result in test_inputs.items():
      policy = ExitPolicy(*rules)
      self.assertEquals(expected_result, policy.is_exiting_allowed())
  
  def test_summary_examples(self):
    # checks the summary() method's pydoc examples
    
    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    self.assertEquals("accept 80, 443", policy.summary())
    
    policy = ExitPolicy('accept *:443', 'reject *:1-1024', 'accept *:*')
    self.assertEquals("reject 1-442, 444-1024", policy.summary())
  
  def test_summary_large_ranges(self):
    # checks the summary() method when the policy includes very large port ranges
    
    policy = ExitPolicy('reject *:80-65535', 'accept *:1-65533', 'reject *:*')
    self.assertEquals("accept 1-79", policy.summary())
    
  
  
  def test_microdesc_exit_parsing(self):
    microdesc_exit_policy = stem.exit_policy.MicrodescriptorExitPolicy("accept 80,443")
    
    self.assertEqual(str(microdesc_exit_policy),"accept 80,443")
    
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "accept 80,-443")
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "accept 80,+443")
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "accept 80,66666")
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "reject 80,foo")
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "bar 80,foo")
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "foo")
    self.assertRaises(ValueError, stem.exit_policy.MicrodescriptorExitPolicy, "bar 80-foo")
    
  def test_micodesc_exit_check(self):
    microdesc_exit_policy = stem.exit_policy.MicrodescriptorExitPolicy("accept 80,443")
    
    self.assertTrue(microdesc_exit_policy.check(80))
    self.assertTrue(microdesc_exit_policy.check("www.atagar.com", 443))
    
    self.assertFalse(microdesc_exit_policy.check(22))
    self.assertFalse(microdesc_exit_policy.check("www.atagar.com", 8118))
