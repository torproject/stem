"""
Unit tests for stem.descriptor.hidden_service for version 3.
"""

import base64
import datetime
import functools
import unittest

import stem.client.datatype
import stem.descriptor
import stem.descriptor.hidden_service
import stem.prereq

import test.require

from stem.descriptor.hidden_service import (
  IntroductionPointV3,
  HiddenServiceDescriptorV3,
  OuterLayer,
  InnerLayer,
)

from test.unit.descriptor import (
  get_resource,
  base_expect_invalid_attr,
  base_expect_invalid_attr_for_text,
)

try:
  # added in python 3.3
  from unittest.mock import patch, Mock
except ImportError:
  from mock import patch, Mock

require_sha3 = test.require.needs(stem.prereq._is_sha3_available, 'requires sha3')
require_x25519 = test.require.needs(lambda: stem.descriptor.hidden_service.X25519_AVAILABLE, 'requires openssl x5509')

expect_invalid_attr = functools.partial(base_expect_invalid_attr, HiddenServiceDescriptorV3, 'version', 3)
expect_invalid_attr_for_text = functools.partial(base_expect_invalid_attr_for_text, HiddenServiceDescriptorV3, 'version', 3)

HS_ADDRESS = u'sltib6sxkuxh2scmtuvd5w2g7pahnzkovefxpo4e4ptnkzl5kkq5h2ad.onion'
HS_PUBKEY = b'\x92\xe6\x80\xfaWU.}HL\x9d*>\xdbF\xfb\xc0v\xe5N\xa9\x0bw\xbb\x84\xe3\xe6\xd5e}R\xa1'

EXPECTED_SIGNING_CERT = """\
-----BEGIN ED25519 CERT-----
AQgABl5/AZLmgPpXVS59SEydKj7bRvvAduVOqQt3u4Tj5tVlfVKhAQAgBABUhpfe
/Wd3p/M74DphsGcIMee/npQ9BTzkzCyTyVmDbykek2EciWaOTCVZJVyiKPErngfW
BDwQZ8rhp05oCqhhY3oFHqG9KS7HGzv9g2v1/PrVJMbkfpwu1YK4b3zIZAk=
-----END ED25519 CERT-----\
"""

with open(get_resource('hidden_service_v3')) as descriptor_file:
  HS_DESC_STR = descriptor_file.read()

with open(get_resource('hidden_service_v3_outer_layer')) as outer_layer_file:
  OUTER_LAYER_STR = outer_layer_file.read()

with open(get_resource('hidden_service_v3_inner_layer')) as inner_layer_file:
  INNER_LAYER_STR = inner_layer_file.read()

with open(get_resource('hidden_service_v3_intro_point')) as intro_point_file:
  INTRO_POINT_STR = intro_point_file.read()


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

  @require_sha3
  @test.require.ed25519_support
  def test_decryption(self):
    """
    Decrypt our descriptor and validate its content.
    """

    desc = HiddenServiceDescriptorV3.from_str(HS_DESC_STR)
    inner_layer = desc.decrypt(HS_ADDRESS)

    self.assertEqual(INNER_LAYER_STR, str(inner_layer))
    self.assertEqual(OUTER_LAYER_STR.rstrip('\x00'), str(inner_layer.outer))

  def test_outer_layer(self):
    """
    Parse the outer layer of our test descriptor.
    """

    desc = OuterLayer(OUTER_LAYER_STR)

    self.assertEqual('x25519', desc.auth_type)
    self.assertEqual('WjZCU9sV1oxkxaPcd7/YozeZgq0lEs6DhWyrdYRNJR4=', desc.ephemeral_key)
    self.assertTrue('BsRYMH/No+LgetIFv' in desc.encrypted)

    client = desc.clients['D0Bz0OlEMCg']

    self.assertEqual(16, len(desc.clients))
    self.assertEqual('D0Bz0OlEMCg', client.id)
    self.assertEqual('or3nS3ScSPYfLJuP9osGiQ', client.iv)
    self.assertEqual('B40RdIWhw7kdA7lt3KJPvQ', client.cookie)

  def test_inner_layer(self):
    """
    Parse the inner layer of our test descriptor.
    """

    desc = InnerLayer(INNER_LAYER_STR)

    self.assertEqual([2], desc.formats)
    self.assertEqual(['ed25519'], desc.intro_auth)
    self.assertEqual(True, desc.is_single_service)
    self.assertEqual(4, len(desc.introduction_points))

    intro_point = desc.introduction_points[0]

    self.assertEqual(2, len(intro_point.link_specifiers))

    link_specifier = intro_point.link_specifiers[0]
    self.assertEqual(stem.client.datatype.LinkByFingerprint, type(link_specifier))
    self.assertEqual('CCCCCCCCCCCCCCCCCCCC', link_specifier.fingerprint)

    link_specifier = intro_point.link_specifiers[1]
    self.assertEqual(stem.client.datatype.LinkByIPv4, type(link_specifier))
    self.assertEqual('1.2.3.4', link_specifier.address)
    self.assertEqual(9001, link_specifier.port)

    self.assertEqual('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', intro_point.onion_key_raw)
    self.assertTrue('ID2l9EFNrp' in intro_point.auth_key_cert.to_base64())
    self.assertEqual('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', intro_point.enc_key_raw)
    self.assertTrue('ZvjPt5IfeQ', intro_point.enc_key_cert)
    self.assertEqual(None, intro_point.legacy_key_raw)
    self.assertEqual(None, intro_point.legacy_key_cert)

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

    for line in stem.descriptor.hidden_service.REQUIRED_V3_FIELDS:
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

  @require_sha3
  def test_address_from_public_key(self):
    self.assertEqual(HS_ADDRESS, HiddenServiceDescriptorV3.address_from_public_key(HS_PUBKEY))

  @require_sha3
  def test_public_key_from_address(self):
    self.assertEqual(HS_PUBKEY, HiddenServiceDescriptorV3.public_key_from_address(HS_ADDRESS))
    self.assertRaisesWith(ValueError, "'boom.onion' isn't a valid hidden service v3 address", HiddenServiceDescriptorV3.public_key_from_address, 'boom')
    self.assertRaisesWith(ValueError, 'Bad checksum (expected def7 but was 842e)', HiddenServiceDescriptorV3.public_key_from_address, '5' * 56)

  def test_intro_point_parse(self):
    """
    Parse a v3 introduction point.
    """

    intro_point = IntroductionPointV3.parse(INTRO_POINT_STR)

    self.assertEqual('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', intro_point.onion_key_raw)
    self.assertTrue('0Acq8QW8O7O' in intro_point.auth_key_cert.to_base64())
    self.assertEqual('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', intro_point.enc_key_raw)
    self.assertTrue('4807i5', intro_point.enc_key_cert.to_base64())
    self.assertTrue('JAoGBAMO3' in intro_point.legacy_key_raw)
    self.assertTrue('Ln1ITJ0qP' in intro_point.legacy_key_cert)

  def test_intro_point_encode(self):
    """
    Encode an introduction point back into a string.
    """

    intro_point = IntroductionPointV3.parse(INTRO_POINT_STR)
    self.assertEqual(INTRO_POINT_STR.rstrip(), intro_point.encode())

  @require_x25519
  @test.require.ed25519_support
  def test_intro_point_crypto(self):
    """
    Retrieve IntroductionPointV3 cryptographic materials.
    """

    from cryptography.hazmat.backends.openssl.x25519 import X25519PublicKey

    intro_point = InnerLayer(INNER_LAYER_STR).introduction_points[0]

    self.assertEqual('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', intro_point.onion_key_raw)
    self.assertEqual('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', intro_point.enc_key_raw)

    self.assertTrue(isinstance(intro_point.onion_key(), X25519PublicKey))
    self.assertTrue(isinstance(intro_point.enc_key(), X25519PublicKey))

    self.assertEqual(intro_point.onion_key_raw, base64.b64encode(stem.util._pubkey_bytes(intro_point.onion_key())))
    self.assertEqual(intro_point.enc_key_raw, base64.b64encode(stem.util._pubkey_bytes(intro_point.enc_key())))

    self.assertEqual(None, intro_point.legacy_key_raw)
    self.assertEqual(None, intro_point.legacy_key())

  @patch('stem.prereq.is_crypto_available', Mock(return_value = False))
  def test_intro_point_crypto_without_prereq(self):
    """
    Fetch cryptographic materials when the module is unavailable.
    """

    intro_point = InnerLayer(INNER_LAYER_STR).introduction_points[0]
    self.assertRaisesWith(ImportError, 'cryptography module unavailable', intro_point.onion_key)

  @test.require.ed25519_support
  def test_encode_decode_descriptor(self):
    """
    Encode an HSv3 descriptor and then decode it and make sure you get the intended results.

    This test is from the point of view of the onionbalance, so the object that
    this test generates is the data that onionbalance also has available when
    making onion service descriptors.
    """

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    onion_key = X25519PrivateKey.generate()
    enc_key = X25519PrivateKey.generate()
    auth_key = Ed25519PrivateKey.generate()
    signing_key = Ed25519PrivateKey.generate()

    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours = 54)

    # Build the service
    private_identity_key = Ed25519PrivateKey.from_private_bytes(b'a' * 32)
    public_identity_key = private_identity_key.public_key()

    onion_address = HiddenServiceDescriptorV3.address_from_public_key(stem.util._pubkey_bytes(public_identity_key))

    intro_points = [
      IntroductionPointV3.create('1.1.1.1', 9001, expiration, onion_key, enc_key, auth_key, signing_key),
      IntroductionPointV3.create('2.2.2.2', 9001, expiration, onion_key, enc_key, auth_key, signing_key),
      IntroductionPointV3.create('3.3.3.3', 9001, expiration, onion_key, enc_key, auth_key, signing_key),
    ]

    # TODO: replace with bytes.fromhex() when we drop python 2.x support

    blind_param = bytearray.fromhex('677776AE42464CAAB0DF0BF1E68A5FB651A390A6A8243CF4B60EE73A6AC2E4E3')

    # Build the descriptor
    desc_string = HiddenServiceDescriptorV3.content(ed25519_private_identity_key = private_identity_key, intro_points = intro_points, blinding_param = blind_param)

    # Parse the descriptor
    desc = HiddenServiceDescriptorV3.from_str(desc_string)
    inner_layer = desc.decrypt(onion_address)

    self.assertEqual(3, len(inner_layer.introduction_points))

    for i, intro_point in enumerate(inner_layer.introduction_points):
      original = intro_points[i]

      self.assertEqual(original.enc_key_raw, intro_point.enc_key_raw)
      self.assertEqual(original.onion_key_raw, intro_point.onion_key_raw)
      self.assertEqual(original.auth_key_cert.key, intro_point.auth_key_cert.key)

      self.assertEqual(intro_point.enc_key_raw, base64.b64encode(stem.util._pubkey_bytes(intro_point.enc_key())))
      self.assertEqual(intro_point.onion_key_raw, base64.b64encode(stem.util._pubkey_bytes(intro_point.onion_key())))
      self.assertEqual(intro_point.auth_key_cert.key, stem.util._pubkey_bytes(intro_point.auth_key()))
