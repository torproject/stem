"""
Unit tests for stem.descriptor.hidden_service for version 3.
"""

import functools
import unittest

import stem.descriptor
import stem.prereq

from stem.descriptor.hidden_service import (
  REQUIRED_V3_FIELDS,
  HiddenServiceDescriptorV3,
)

from test.unit.descriptor import (
  get_resource,
  base_expect_invalid_attr,
  base_expect_invalid_attr_for_text,
)

expect_invalid_attr = functools.partial(base_expect_invalid_attr, HiddenServiceDescriptorV3, 'version', 3)
expect_invalid_attr_for_text = functools.partial(base_expect_invalid_attr_for_text, HiddenServiceDescriptorV3, 'version', 3)

EXPECTED_SIGNING_CERT = """\
-----BEGIN ED25519 CERT-----
AQgABqKwAQVql1QZETyEwJjg+Cv6f2w/cp+c3juj01NPBaJqihboAQAgBACx+FKK
oDrFE1+ztSxzN8sApKOb5UuDtoe/E03DxZU5+r/K5AV6G0hYn21V7Xbu2pZHvIkT
2oVY4hypWNJE58eFBRFRzBA0J2h0GyFs1pIuRh5QDJuxB5j92V0aRCNZFgM=
-----END ED25519 CERT-----\
"""


class TestHiddenServiceDescriptorV3(unittest.TestCase):
  def test_for_decrypt(self):
    """
    Parse a test descriptor (used while making the v3 decode function)...

      sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion
    """

    if not stem.prereq.is_crypto_available(ed25519 = True):
      self.skipTest('(requires cryptography v2.6)')
      return

    with open(get_resource('hidden_service_v3_test'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor-3 1.0', validate = True))

    self.assertEqual(3, desc.version)
    self.assertEqual(180, desc.lifetime)
    self.assertEqual(42, desc.revision_counter)

    desc._decrypt('sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion')

  def test_for_riseup(self):
    """
    Parse riseup's descriptor...

      vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion
    """

    with open(get_resource('hidden_service_v3'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor-3 1.0', validate = True, skip_crypto_validation = True))

    self.assertEqual(3, desc.version)
    self.assertEqual(180, desc.lifetime)
    self.assertEqual(EXPECTED_SIGNING_CERT, desc.signing_cert)
    self.assertEqual(15, desc.revision_counter)
    self.assertTrue('k9uKnDpxhkH0h1h' in desc.superencrypted)
    self.assertEqual('wdc7ffr+dPZJ/mIQ1l4WYqNABcmsm6SHW/NL3M3wG7bjjqOJWoPR5TimUXxH52n5Zk0Gc7hl/hz3YYmAx5MvAg', desc.signature)

  def test_required_fields(self):
    """
    Check that we require the mandatory fields.
    """

    line_to_attr = {
      'hs-descriptor': 'version',
      'descriptor-lifetime': 'lifetime',
      'descriptor-signing-key-cert': 'signing_cert',
      'revision-counter': 'revision_counter',
      'superencrypted': 'superencrypted',
      'signature': 'signature',
    }

    for line in REQUIRED_V3_FIELDS:
      desc_text = HiddenServiceDescriptorV3.content(exclude = (line,))
      expect_invalid_attr_for_text(self, desc_text, line_to_attr[line], None)

  def test_invalid_version(self):
    """
    Checks that our version field expects a numeric value.
    """

    test_values = (
      '',
      '-10',
      'hello',
    )

    for test_value in test_values:
      expect_invalid_attr(self, {'hs-descriptor': test_value}, 'version')

  def test_invalid_lifetime(self):
    """
    Checks that our lifetime field expects a numeric value.
    """

    test_values = (
      '',
      '-10',
      'hello',
    )

    for test_value in test_values:
      expect_invalid_attr(self, {'descriptor-lifetime': test_value}, 'lifetime')

  def test_invalid_revision_counter(self):
    """
    Checks that our revision counter field expects a numeric value.
    """

    test_values = (
      '',
      '-10',
      'hello',
    )

    for test_value in test_values:
      expect_invalid_attr(self, {'revision-counter': test_value}, 'revision_counter')
