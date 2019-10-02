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

HS_ADDRESS = 'sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion'

EXPECTED_SIGNING_CERT = """\
-----BEGIN ED25519 CERT-----
AQgABl5/AZLmgPpXVS59SEydKj7bRvvAduVOqQt3u4Tj5tVlfVKhAQAgBABUhpfe
/Wd3p/M74DphsGcIMee/npQ9BTzkzCyTyVmDbykek2EciWaOTCVZJVyiKPErngfW
BDwQZ8rhp05oCqhhY3oFHqG9KS7HGzv9g2v1/PrVJMbkfpwu1YK4b3zIZAk=
-----END ED25519 CERT-----\
"""


class TestHiddenServiceDescriptorV3(unittest.TestCase):
  def test_real_descriptor(self):
    """
    Parse a descriptor for a testing hidden service from asn...

      sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion
    """

    with open(get_resource('hidden_service_v3'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor-3 1.0', validate = True))

    self.assertEqual(3, desc.version)
    self.assertEqual(180, desc.lifetime)
    self.assertEqual(EXPECTED_SIGNING_CERT, str(desc.signing_cert))
    self.assertEqual(42, desc.revision_counter)
    self.assertTrue('eaH8VdaTKS' in desc.superencrypted)
    self.assertEqual('aglChCQF+lbzKgyxJJTpYGVShV/GMDRJ4+cRGCp+a2y/yX/tLSh7hzqI7rVZrUoGj74Xr1CLMYO3fXYCS+DPDQ', desc.signature)

    if stem.prereq.is_crypto_available(ed25519 = True) and stem.prereq._is_sha3_available():
      with open(get_resource('hidden_service_v3_outer_layer'), 'rb') as outer_layer_file:
        self.assertEqual(outer_layer_file.read(), desc._decrypt(HS_ADDRESS, outer_layer = True))

      with open(get_resource('hidden_service_v3_inner_layer'), 'rb') as outer_layer_file:
        self.assertEqual(outer_layer_file.read(), desc._decrypt(HS_ADDRESS, outer_layer = False))

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

  def test_public_key_from_address(self):
    if not stem.prereq.is_crypto_available(ed25519 = True):
      self.skipTest('(requires cryptography ed25519 support)')
      return
    elif not stem.prereq._is_sha3_available():
      self.skipTest('(requires sha3 support)')
      return

    self.assertEqual(b'\x92\xe6\x80\xfaWU.}HL\x9d*>\xdbF\xfb\xc0v\xe5N\xa9\x0bw\xbb\x84\xe3\xe6\xd5e}R\xa1', HiddenServiceDescriptorV3._public_key_from_address(HS_ADDRESS))
    self.assertRaisesWith(ValueError, "'boom.onion' isn't a valid hidden service v3 address", HiddenServiceDescriptorV3._public_key_from_address, 'boom')
    self.assertRaisesWith(ValueError, 'Bad checksum (expected def7 but was 842e)', HiddenServiceDescriptorV3._public_key_from_address, '5' * 56)
