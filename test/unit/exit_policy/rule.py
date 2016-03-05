"""
Unit tests for the stem.exit_policy.ExitPolicyRule class.
"""

import unittest

from stem.exit_policy import AddressType, ExitPolicyRule, MicroExitPolicy


class TestExitPolicyRule(unittest.TestCase):
  def test_accept_or_reject(self):
    self.assertTrue(ExitPolicyRule('accept *:*').is_accept)
    self.assertFalse(ExitPolicyRule('reject *:*').is_accept)

    invalid_inputs = (
      'accept',
      'reject',
      'accept\t*:*',
      'accept\n*:*',
      'acceptt *:*',
      'rejectt *:*',
      'blarg *:*',
      ' *:*',
      '*:*',
      '',
    )

    for rule_arg in invalid_inputs:
      self.assertRaises(ValueError, ExitPolicyRule, rule_arg)

  def test_with_multiple_spaces(self):
    rule = ExitPolicyRule('accept    *:80')
    self.assertEqual('accept *:80', str(rule))

    policy = MicroExitPolicy('accept      80,443')
    self.assertTrue(policy.can_exit_to('75.119.206.243', 80))

  def test_str_unchanged(self):
    # provides a series of test inputs where the str() representation should
    # match the input rule

    test_inputs = (
      'accept *:*',
      'reject *:*',

      'accept *:80',
      'accept *:80-443',
      'accept 127.0.0.1:80',
      'accept 87.0.0.1/24:80',
      'accept 156.5.38.3/255.255.0.255:80',
      'accept [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:80',
      'accept [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]/32:80',
    )

    for rule_arg in test_inputs:
      rule = ExitPolicyRule(rule_arg)
      self.assertEqual(rule_arg, str(rule))

  def test_str_changed(self):
    # some instances where our rule is valid but won't match our str() representation
    test_inputs = {
      'accept 10.0.0.1/32:80': 'accept 10.0.0.1:80',
      'accept 192.168.0.1/255.255.255.0:80': 'accept 192.168.0.1/24:80',
      'accept [::]/32:*': 'accept [0000:0000:0000:0000:0000:0000:0000:0000]/32:*',
      'accept [::]/128:*': 'accept [0000:0000:0000:0000:0000:0000:0000:0000]:*',

      'accept6 *:*': 'accept [0000:0000:0000:0000:0000:0000:0000:0000]/0:*',
      'reject6 *:*': 'reject [0000:0000:0000:0000:0000:0000:0000:0000]/0:*',
      'accept6 [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:*': 'accept [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:*',
      'reject6 [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:*': 'reject [FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:*',

      'accept *4:*': 'accept 0.0.0.0/0:*',
      'accept *6:*': 'accept [0000:0000:0000:0000:0000:0000:0000:0000]/0:*',
      'accept6 *4:*': 'accept 0.0.0.0/0:*',
      'accept6 *6:*': 'accept [0000:0000:0000:0000:0000:0000:0000:0000]/0:*',
    }

    for rule_arg, expected_str in test_inputs.items():
      rule = ExitPolicyRule(rule_arg)
      self.assertEqual(expected_str, str(rule))

  def test_valid_wildcard(self):
    test_inputs = {
      'reject *:*': (True, True),
      'reject *:80': (True, False),
      'accept 192.168.0.1:*': (False, True),
      'accept 192.168.0.1:80': (False, False),

      'reject *4:*': (False, True),
      'reject *6:*': (False, True),
      'reject6 *4:*': (False, True),
      'reject6 *6:*': (False, True),

      'reject 127.0.0.1/0:*': (False, True),
      'reject 127.0.0.1/0.0.0.0:*': (False, True),
      'reject 127.0.0.1/16:*': (False, True),
      'reject 127.0.0.1/32:*': (False, True),
      'reject [0000:0000:0000:0000:0000:0000:0000:0000]/0:80': (False, False),
      'reject [0000:0000:0000:0000:0000:0000:0000:0000]/64:80': (False, False),
      'reject [0000:0000:0000:0000:0000:0000:0000:0000]/128:80': (False, False),

      'reject6 *:*': (False, True),
      'reject6 *:80': (False, False),
      'reject6 [0000:0000:0000:0000:0000:0000:0000:0000]/128:80': (False, False),

      'accept 192.168.0.1:0-65535': (False, True),
      'accept 192.168.0.1:1-65535': (False, True),
      'accept 192.168.0.1:2-65535': (False, False),
      'accept 192.168.0.1:1-65534': (False, False),
    }

    for rule_arg, attr in test_inputs.items():
      is_address_wildcard, is_port_wildcard = attr

      rule = ExitPolicyRule(rule_arg)
      self.assertEqual(is_address_wildcard, rule.is_address_wildcard(), '%s (wildcard expected %s and actually %s)' % (rule_arg, is_address_wildcard, rule.is_address_wildcard()))
      self.assertEqual(is_port_wildcard, rule.is_port_wildcard())

    # check that when appropriate a /0 is reported as *not* being a wildcard

    rule = ExitPolicyRule('reject 127.0.0.1/0:*')
    rule._submask_wildcard = False
    self.assertEqual(False, rule.is_address_wildcard())

    rule = ExitPolicyRule('reject [0000:0000:0000:0000:0000:0000:0000:0000]/0:80')
    rule._submask_wildcard = False
    self.assertEqual(False, rule.is_address_wildcard())

  def test_invalid_wildcard(self):
    test_inputs = (
      'reject */16:*',
      'reject 127.0.0.1/*:*',
      'reject *:0-*',
      'reject *:*-15',
    )

    for rule_arg in test_inputs:
      self.assertRaises(ValueError, ExitPolicyRule, rule_arg)

  def test_wildcard_attributes(self):
    rule = ExitPolicyRule('reject *:*')
    self.assertEqual(AddressType.WILDCARD, rule.get_address_type())
    self.assertEqual(None, rule.address)
    self.assertEqual(None, rule.get_mask())
    self.assertEqual(None, rule.get_masked_bits())
    self.assertEqual(1, rule.min_port)
    self.assertEqual(65535, rule.max_port)

  def test_valid_ipv4_addresses(self):
    test_inputs = {
      '0.0.0.0': ('0.0.0.0', '255.255.255.255', 32),
      '127.0.0.1/32': ('127.0.0.1', '255.255.255.255', 32),
      '192.168.0.50/24': ('192.168.0.50', '255.255.255.0', 24),
      '255.255.255.255/0': ('255.255.255.255', '0.0.0.0', 0),
    }

    for rule_addr, attr in test_inputs.items():
      address, mask, masked_bits = attr

      rule = ExitPolicyRule('accept %s:*' % rule_addr)
      self.assertEqual(AddressType.IPv4, rule.get_address_type())
      self.assertEqual(address, rule.address)
      self.assertEqual(mask, rule.get_mask())
      self.assertEqual(masked_bits, rule.get_masked_bits())

  def test_invalid_ipv4_addresses(self):
    test_inputs = (
      '256.0.0.0',
      '-1.0.0.0',
      '0.0.0',
      '0.0.0.',
      '0.0.0.a',
      '127.0.0.1/-1',
      '127.0.0.1/33',
    )

    for rule_addr in test_inputs:
      self.assertRaises(ValueError, ExitPolicyRule, 'accept %s:*' % rule_addr)

  def test_valid_ipv6_addresses(self):
    test_inputs = {
      '[fe80:0000:0000:0000:0202:b3ff:fe1e:8329]':
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329',
         'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 128),
      '[FE80::0202:b3ff:fe1e:8329]':
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329',
         'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 128),
      '[0000:0000:0000:0000:0000:0000:0000:0000]/0':
        ('0000:0000:0000:0000:0000:0000:0000:0000',
         '0000:0000:0000:0000:0000:0000:0000:0000', 0),
      '[::]':
        ('0000:0000:0000:0000:0000:0000:0000:0000',
         'FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF', 128),
    }

    for rule_addr, attr in test_inputs.items():
      address, mask, masked_bits = attr

      rule = ExitPolicyRule('accept %s:*' % rule_addr)
      self.assertEqual(AddressType.IPv6, rule.get_address_type())
      self.assertEqual(address, rule.address)
      self.assertEqual(mask, rule.get_mask())
      self.assertEqual(masked_bits, rule.get_masked_bits())

  def test_invalid_ipv6_addresses(self):
    test_inputs = (
      'fe80::0202:b3ff:fe1e:8329',
      '[fe80::0202:b3ff:fe1e:8329',
      'fe80::0202:b3ff:fe1e:8329]',
      '[fe80::0202:b3ff:fe1e:832g]',
      '[fe80:::b3ff:fe1e:8329]',
      '[fe80::b3ff::fe1e:8329]',
      '[fe80::0202:b3ff:fe1e:8329]/-1',
      '[fe80::0202:b3ff:fe1e:8329]/129',
    )

    for rule_addr in test_inputs:
      self.assertRaises(ValueError, ExitPolicyRule, 'accept %s:*' % rule_addr)

  def test_valid_ports(self):
    test_inputs = {
      '0': (0, 0),
      '1': (1, 1),
      '80': (80, 80),
      '80-443': (80, 443),
    }

    for rule_port, attr in test_inputs.items():
      min_port, max_port = attr

      rule = ExitPolicyRule('accept 127.0.0.1:%s' % rule_port)
      self.assertEqual(min_port, rule.min_port)
      self.assertEqual(max_port, rule.max_port)

  def test_invalid_ports(self):
    test_inputs = (
      '65536',
      'a',
      '5-3',
      '5-',
      '-3',
    )

    for rule_port in test_inputs:
      self.assertRaises(ValueError, ExitPolicyRule, 'accept 127.0.0.1:%s' % rule_port)

  def test_is_match_wildcard(self):
    test_inputs = {
      'reject *:*': {
        ('192.168.0.1', 80): True,
        ('0.0.0.0', 80): True,
        ('255.255.255.255', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 80): True,
        ('[FE80:0000:0000:0000:0202:B3FF:FE1E:8329]', 80): True,
        ('192.168.0.1', None): True,
        (None, 80, False): True,
        (None, 80, True): True,
        (None, None, False): True,
        (None, None, True): True,
      },
      'reject 255.255.255.255/0:*': {
        ('192.168.0.1', 80): True,
        ('0.0.0.0', 80): True,
        ('255.255.255.255', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 80): False,
        ('[FE80:0000:0000:0000:0202:B3FF:FE1E:8329]', 80): False,
        ('192.168.0.1', None): True,
        (None, 80, False): False,
        (None, 80, True): True,
        (None, None, False): False,
        (None, None, True): True,
      },
      'reject *4:*': {
        ('192.168.0.1', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 80): False,
      },
      'reject *6:*': {
        ('192.168.0.1', 80): False,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 80): True,
      },
    }

    for rule_arg, matches in test_inputs.items():
      rule = ExitPolicyRule(rule_arg)
      rule._submask_wildcard = False

      for match_args, expected_result in matches.items():
        self.assertEqual(expected_result, rule.is_match(*match_args))

    # port zero is special in that exit policies can include it, but it's not
    # something that we can match against

    rule = ExitPolicyRule('reject *:*')
    self.assertRaises(ValueError, rule.is_match, '127.0.0.1', 0)

  def test_is_match_ipv4(self):
    test_inputs = {
      'reject 192.168.0.50:*': {
        ('192.168.0.50', 80): True,
        ('192.168.0.51', 80): False,
        ('192.168.0.49', 80): False,
        (None, 80, False): False,
        (None, 80, True): True,
        ('192.168.0.50', None): True,
      },
      'reject 0.0.0.0/24:*': {
        ('0.0.0.0', 80): True,
        ('0.0.0.1', 80): True,
        ('0.0.0.255', 80): True,
        ('0.0.1.0', 80): False,
        ('0.1.0.0', 80): False,
        ('1.0.0.0', 80): False,
        (None, 80, False): False,
        (None, 80, True): True,
        ('0.0.0.0', None): True,
      },
    }

    for rule_arg, matches in test_inputs.items():
      rule = ExitPolicyRule(rule_arg)

      for match_args, expected_result in matches.items():
        self.assertEqual(expected_result, rule.is_match(*match_args))

  def test_is_match_ipv6(self):
    test_inputs = {
      'reject [FE80:0000:0000:0000:0202:B3FF:FE1E:8329]:*': {
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 80): True,
        ('fe80:0000:0000:0000:0202:b3ff:fe1e:8329', 80): True,
        ('[FE80:0000:0000:0000:0202:B3FF:FE1E:8329]', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8330', 80): False,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8328', 80): False,
        (None, 80, False): False,
        (None, 80, True): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', None): True,
      },
      'reject [FE80:0000:0000:0000:0202:B3FF:FE1E:8329]/112:*': {
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:0000', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:FFFF', 80): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1F:8329', 80): False,
        ('FE81:0000:0000:0000:0202:B3FF:FE1E:8329', 80): False,
        (None, 80, False): False,
        (None, 80, True): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', None, False): True,
        ('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', None, True): True,
      },
    }

    for rule_arg, matches in test_inputs.items():
      rule = ExitPolicyRule(rule_arg)

      for match_args, expected_result in matches.items():
        self.assertEqual(expected_result, rule.is_match(*match_args))

  def test_is_match_port(self):
    test_inputs = {
      'reject *:80': {
        ('192.168.0.50', 80): True,
        ('192.168.0.50', 81): False,
        ('192.168.0.50', 79): False,
        (None, 80): True,
        ('192.168.0.50', None, False): False,
        ('192.168.0.50', None, True): True,
      },
      'reject *:80-85': {
        ('192.168.0.50', 79): False,
        ('192.168.0.50', 80): True,
        ('192.168.0.50', 83): True,
        ('192.168.0.50', 85): True,
        ('192.168.0.50', 86): False,
        (None, 83): True,
        ('192.168.0.50', None, False): False,
        ('192.168.0.50', None, True): True,
      },
    }

    for rule_arg, matches in test_inputs.items():
      rule = ExitPolicyRule(rule_arg)

      for match_args, expected_result in matches.items():
        self.assertEqual(expected_result, rule.is_match(*match_args))

  def test_ipv6_only_entries(self):
    # accept6/reject6 shouldn't match anything when given an ipv4 addresses

    rule = ExitPolicyRule('accept6 192.168.0.1/0:*')
    self.assertTrue(rule._skip_rule)
    self.assertFalse(rule.is_match('192.168.0.1'))
    self.assertFalse(rule.is_match('FE80:0000:0000:0000:0202:B3FF:FE1E:8329'))
    self.assertFalse(rule.is_match())

    rule = ExitPolicyRule('accept6 *4:*')
    self.assertTrue(rule._skip_rule)

    # wildcards match all ipv6 but *not* ipv4

    rule = ExitPolicyRule('accept6 *:*')
    self.assertTrue(rule.is_match('FE80:0000:0000:0000:0202:B3FF:FE1E:8329', 443))
    self.assertFalse(rule.is_match('192.168.0.1', 443))
