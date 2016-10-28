"""
Unit tests for the stem.exit_policy.ExitPolicy class.
"""

import pickle
import unittest

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

from stem.exit_policy import (
  DEFAULT_POLICY_RULES,
  get_config_policy,
  ExitPolicy,
  MicroExitPolicy,
  ExitPolicyRule,
)


class TestExitPolicy(unittest.TestCase):
  def test_example(self):
    # tests the ExitPolicy and MicroExitPolicy pydoc examples
    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    self.assertEqual('accept *:80, accept *:443, reject *:*', str(policy))
    self.assertEqual('accept 80, 443', policy.summary())
    self.assertTrue(policy.can_exit_to('75.119.206.243', 80))

    policy = MicroExitPolicy('accept 80,443')
    self.assertTrue(policy.can_exit_to('75.119.206.243', 80))

  def test_constructor(self):
    # The ExitPolicy constructor takes a series of string or ExitPolicyRule
    # entries. Extra whitespace is ignored to make csvs easier to handle.

    expected_policy = ExitPolicy(
      ExitPolicyRule('accept *:80'),
      ExitPolicyRule('accept *:443'),
      ExitPolicyRule('reject *:*'),
    )

    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    self.assertEqual(expected_policy, policy)

    policy = ExitPolicy(*'accept *:80, accept *:443, reject *:*'.split(','))
    self.assertEqual(expected_policy, policy)

    # checks that we truncate after getting a catch-all policy

    policy = ExitPolicy(*'accept *:80, accept *:443, reject *:*, accept *:20-50'.split(','))
    self.assertEqual(expected_policy, policy)

    # checks that we compress redundant policies

    policy = ExitPolicy(*'reject *:80, reject *:443, reject *:*'.split(','))
    self.assertEqual(ExitPolicy('reject *:*'), policy)

  def test_can_exit_to(self):
    # Basic sanity test for our can_exit_to() method. Most of the interesting
    # use cases (ip masks, wildcards, etc) are covered by the ExitPolicyRule
    # tests.

    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')

    for index in range(1, 500):
      ip_addr = '%i.%i.%i.%i' % (index / 2, index / 2, index / 2, index / 2)
      expected_result = index in (80, 443)

      self.assertEqual(expected_result, policy.can_exit_to(ip_addr, index))
      self.assertEqual(expected_result, policy.can_exit_to(port = index))

  def test_can_exit_to_strictness(self):
    # Check our 'strict' argument.

    policy = ExitPolicy('reject 1.0.0.0/8:80', 'accept *:*')
    self.assertEqual(False, policy.can_exit_to(None, 80, strict = True))  # can't exit to *all* instances of port 80
    self.assertEqual(True, policy.can_exit_to(None, 80, strict = False))  # can exit to *an* instance of port 80

    policy = ExitPolicy('accept 1.0.0.0/8:80', 'reject *:*')
    self.assertEqual(False, policy.can_exit_to(None, 80, strict = True))  # can't exit to *all* instances of port 80
    self.assertEqual(True, policy.can_exit_to(None, 80, strict = False))  # can exit to *an* instance of port 80

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
      self.assertEqual(expected_result, policy.is_exiting_allowed())

  def test_summary_examples(self):
    # checks the summary() method's pydoc examples

    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    self.assertEqual('accept 80, 443', policy.summary())

    policy = ExitPolicy('accept *:443', 'reject *:1-1024', 'accept *:*')
    self.assertEqual('reject 1-442, 444-1024', policy.summary())

  def test_summary_large_ranges(self):
    # checks the summary() method when the policy includes very large port ranges

    policy = ExitPolicy('reject *:80-65535', 'accept *:1-65533', 'reject *:*')
    self.assertEqual('accept 1-79', policy.summary())

  def test_non_private_non_default_policy(self):
    policy = get_config_policy('reject *:80-65535, accept *:1-65533, reject *:*')

    for rule in policy:
      self.assertFalse(rule.is_private())
      self.assertFalse(rule.is_default())

    self.assertFalse(policy.has_private())
    self.assertFalse(policy.has_default())

    self.assertEqual(policy, policy.strip_private())
    self.assertEqual(policy, policy.strip_default())

  def test_all_private_policy(self):
    for port in ('*', '80', '1-1024'):
      private_policy = get_config_policy('reject private:%s' % port, '12.34.56.78')

      for rule in private_policy:
        self.assertTrue(rule.is_private())

      self.assertEqual(ExitPolicy(), private_policy.strip_private())

    # though not commonly done, technically private policies can be accept rules too

    private_policy = get_config_policy('accept private:*')
    self.assertEqual(ExitPolicy(), private_policy.strip_private())

  @patch('socket.gethostname', Mock(side_effect = IOError('no address')))
  def test_all_private_policy_without_network(self):
    for rule in get_config_policy('reject private:80, accept *:80'):
      # all rules except the ending accept are part of the private policy
      self.assertEqual(str(rule) != 'accept *:80', rule.is_private())

  def test_all_default_policy(self):
    policy = ExitPolicy(*DEFAULT_POLICY_RULES)

    for rule in policy:
      self.assertTrue(rule.is_default())

    self.assertTrue(policy.has_default())
    self.assertEqual(ExitPolicy(), policy.strip_default())

  def test_mixed_private_policy(self):
    policy = get_config_policy('accept *:80, reject private:1-65533, accept *:*')

    for rule in policy:
      self.assertTrue(rule.is_accept != rule.is_private())  # only reject rules are the private ones

    self.assertEqual(get_config_policy('accept *:80, accept *:*'), policy.strip_private())

  def test_mixed_default_policy(self):
    policy = ExitPolicy('accept *:80', 'accept 127.0.0.1:1-65533', *DEFAULT_POLICY_RULES)

    for rule in policy:
      # only accept-all and reject rules are the default ones
      self.assertTrue(rule.is_accept != rule.is_default() or (rule.is_accept and rule.is_address_wildcard() and rule.is_port_wildcard()))

    self.assertEqual(get_config_policy('accept *:80, accept 127.0.0.1:1-65533'), policy.strip_default())

  def test_get_config_policy_with_ipv6(self):
    # ensure our constructor accepts addresses both with and without brackets
    self.assertTrue(get_config_policy('reject private:80', 'fe80:0000:0000:0000:0202:b3ff:fe1e:8329').is_exiting_allowed())
    self.assertTrue(get_config_policy('reject private:80', '[fe80:0000:0000:0000:0202:b3ff:fe1e:8329]').is_exiting_allowed())

  def test_str(self):
    # sanity test for our __str__ method

    policy = ExitPolicy('  accept *:80\n', '\taccept *:443')
    self.assertEqual('accept *:80, accept *:443', str(policy))

    policy = ExitPolicy('reject 0.0.0.0/255.255.255.0:*', 'accept *:*')
    self.assertEqual('reject 0.0.0.0/24:*, accept *:*', str(policy))

  def test_iter(self):
    # sanity test for our __iter__ method

    rules = [
      ExitPolicyRule('accept *:80'),
      ExitPolicyRule('accept *:443'),
      ExitPolicyRule('reject *:*'),
    ]

    self.assertEqual(rules, list(ExitPolicy(*rules)))
    self.assertEqual(rules, list(ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')))

  def test_microdescriptor_parsing(self):
    # mapping between inputs and if they should succeed or not
    test_inputs = {
      'accept 80': True,
      'accept 80,443': True,
      '': False,
      'accept': False,
      'accept ': False,
      'accept\t80,443': False,
      'accept 80, 443': False,
      'accept 80,\t443': False,
      '80,443': False,
      'accept 80,-443': False,
      'accept 80,+443': False,
      'accept 80,66666': False,
      'reject 80,foo': False,
      'bar 80,443': False,
    }

    for policy_arg, expect_success in test_inputs.items():
      try:
        policy = MicroExitPolicy(policy_arg)

        if expect_success:
          self.assertEqual(policy_arg, str(policy))
        else:
          self.fail()
      except ValueError:
        if expect_success:
          self.fail()

  def test_microdescriptor_attributes(self):
    # checks that its is_accept attribute is properly set

    # single port
    policy = MicroExitPolicy('accept 443')
    self.assertTrue(policy.is_accept)

    # multiple ports
    policy = MicroExitPolicy('accept 80,443')
    self.assertTrue(policy.is_accept)

    # port range
    policy = MicroExitPolicy('reject 1-1024')
    self.assertFalse(policy.is_accept)

  def test_microdescriptor_can_exit_to(self):
    test_inputs = {
      'accept 443': {442: False, 443: True, 444: False},
      'reject 443': {442: True, 443: False, 444: True},
      'accept 80,443': {80: True, 443: True, 10: False},
      'reject 1-1024': {1: False, 1024: False, 1025: True},
    }

    for policy_arg, attr in test_inputs.items():
      policy = MicroExitPolicy(policy_arg)

      for port, expected_value in attr.items():
        self.assertEqual(expected_value, policy.can_exit_to(port = port))

    # address argument should be ignored
    policy = MicroExitPolicy('accept 80,443')

    self.assertFalse(policy.can_exit_to('127.0.0.1', 79))
    self.assertTrue(policy.can_exit_to('127.0.0.1', 80))

  def test_get_config_policy(self):
    test_inputs = {
      '': ExitPolicy(),
      'reject *': ExitPolicy('reject *:*'),
      'reject *:*': ExitPolicy('reject *:*'),
      'reject private': ExitPolicy(
        'reject 0.0.0.0/8:*',
        'reject 169.254.0.0/16:*',
        'reject 127.0.0.0/8:*',
        'reject 192.168.0.0/16:*',
        'reject 10.0.0.0/8:*',
        'reject 172.16.0.0/12:*',
        'reject 12.34.56.78:*',
      ),
      'accept *:80, reject *': ExitPolicy(
        'accept *:80',
        'reject *:*',
      ),
      '  accept *:80,     reject *   ': ExitPolicy(
        'accept *:80',
        'reject *:*',
      ),
    }

    for test_input, expected in test_inputs.items():
      self.assertEqual(expected, get_config_policy(test_input, '12.34.56.78'))

    test_inputs = (
      'blarg',
      'accept *:*:*',
      'acceptt *:80',
      'accept 257.0.0.1:80',
      'accept *:999999',
    )

    for test_input in test_inputs:
      self.assertRaises(ValueError, get_config_policy, test_input)

  def test_pickleability(self):
    """
    Checks that we can unpickle ExitPolicy instances.
    """

    policy = ExitPolicy('accept *:80', 'accept *:443', 'reject *:*')
    self.assertTrue(policy.can_exit_to('74.125.28.106', 80))

    encoded_policy = pickle.dumps(policy)
    restored_policy = pickle.loads(encoded_policy)

    self.assertEqual(policy, restored_policy)
    self.assertTrue(restored_policy.is_exiting_allowed())
    self.assertTrue(restored_policy.can_exit_to('74.125.28.106', 80))
