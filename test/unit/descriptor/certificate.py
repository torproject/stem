"""
Unit tests for stem.descriptor.certificate.
"""

import base64
import datetime
import re
import unittest

import stem.descriptor.certificate
import stem.prereq
import test.runner

from stem.descriptor.certificate import ED25519_SIGNATURE_LENGTH, CertType, ExtensionType, ExtensionFlag, Ed25519Certificate, Ed25519CertificateV1, Ed25519Extension
from test.unit.descriptor import get_resource

ED25519_CERT = """
AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABnprVR
ptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8sGG8lTjx1
g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98Ljhdp2w4=
""".strip()

EXPECTED_CERT_KEY = '\xa5\xb6\x1a\x80D\x0fR#cp:\x7f\xa1\x8d\xa8\x11%\xe4\x0f7|=\x99k\xdb\xa9\x1aG\xb9\xd4\x91\xaa'
EXPECTED_EXTENSION_DATA = 'g\xa6\xb5Q\xa6\xd2+\xe3v\xd6>\x8d\x9f#:7\xb8\xec\xb0~\x83+\xaf*k\xa5\xb9\xb8\x1e\x10\xa4d'
EXPECTED_SIGNATURE = '\xc6\x8e\xd3\xae\x0b?\xedJ6\xe2\xef\x95\xcf,\x18o%N<u\x83\x897\x10\xbb\x96b\x01\xd8YNk\x02&\xbb\x9e^ Q\xf0Y8G\xc7\x01\xf2\x84K\xb9ww\xad\xdd\x04H\xc4_\xdf\x0b\x8e\x17i\xdb\x0e'


def certificate(version = 1, cert_type = 4, extension_data = []):
  """
  Provides base64 encoded Ed25519 certifificate content.

  :param int version: certificate version
  :param int cert_type: certificate type
  :param list extension_data: extensions to embed within the certificate
  """

  return base64.b64encode(''.join([
    chr(version),
    chr(cert_type),
    b'\x00' * 4,               # expiration date, leaving this as the epoch
    b'\x01',                   # key type
    b'\x03' * 32,              # key
    chr(len(extension_data)),  # extension count
    b''.join(extension_data),
    b'\x01' * ED25519_SIGNATURE_LENGTH]))


class TestEd25519Certificate(unittest.TestCase):
  def assert_raises(self, parse_arg, exc_msg):
    self.assertRaisesRegexp(ValueError, re.escape(exc_msg), Ed25519Certificate.parse, parse_arg)

  def test_basic_parsing(self):
    """
    Parse a basic test certificate.
    """

    signing_key = b'\x11' * 32
    cert_bytes = certificate(extension_data = [b'\x00\x20\x04\x07' + signing_key, b'\x00\x00\x05\x04'])
    cert = Ed25519Certificate.parse(cert_bytes)

    self.assertEqual(Ed25519CertificateV1, type(cert))
    self.assertEqual(1, cert.version)
    self.assertEqual(cert_bytes, cert.encoded)
    self.assertEqual(CertType.SIGNING, cert.type)
    self.assertEqual(datetime.datetime(1970, 1, 1, 1, 0), cert.expiration)
    self.assertEqual(1, cert.key_type)
    self.assertEqual(b'\x03' * 32, cert.key)
    self.assertEqual(b'\x01' * ED25519_SIGNATURE_LENGTH, cert.signature)

    self.assertEqual([
      Ed25519Extension(type = ExtensionType.HAS_SIGNING_KEY, flags = [ExtensionFlag.AFFECTS_VALIDATION, ExtensionFlag.UNKNOWN], flag_int = 7, data = signing_key),
      Ed25519Extension(type = 5, flags = [ExtensionFlag.UNKNOWN], flag_int = 4, data = b''),
    ], cert.extensions)

    self.assertEqual(ExtensionType.HAS_SIGNING_KEY, cert.extensions[0].type)
    self.assertTrue(cert.is_expired())

  def test_with_real_cert(self):
    """
    Parse a certificate from a real server descriptor.
    """

    cert = Ed25519Certificate.parse(ED25519_CERT)

    self.assertEqual(Ed25519CertificateV1, type(cert))
    self.assertEqual(1, cert.version)
    self.assertEqual(ED25519_CERT, cert.encoded)
    self.assertEqual(CertType.SIGNING, cert.type)
    self.assertEqual(datetime.datetime(2015, 8, 28, 19, 0), cert.expiration)
    self.assertEqual(1, cert.key_type)
    self.assertEqual(EXPECTED_CERT_KEY, cert.key)
    self.assertEqual([Ed25519Extension(type = 4, flags = [], flag_int = 0, data = EXPECTED_EXTENSION_DATA)], cert.extensions)
    self.assertEqual(EXPECTED_SIGNATURE, cert.signature)

  def test_non_base64(self):
    """
    Parse data that isn't base64 encoded.
    """

    self.assert_raises('\x02\x0323\x04', "Ed25519 certificate wasn't propoerly base64 encoded (Incorrect padding):")

  def test_too_short(self):
    """
    Parse data that's too short to be a valid certificate.
    """

    self.assert_raises('', "Ed25519 certificate wasn't propoerly base64 encoded (empty):")
    self.assert_raises('AQQABhtZAaW2GoBED1IjY3A6', 'Ed25519 certificate was 18 bytes, but should be at least 104')

  def test_with_invalid_version(self):
    """
    We cannot support other certificate versions until they're documented.
    Assert we raise if we don't handle a cert version yet.
    """

    self.assert_raises(certificate(version = 2), 'Ed25519 certificate is version 2. Parser presently only supports version 1.')

  def test_with_invalid_cert_type(self):
    """
    Provide an invalid certificate version. Tor specifies a couple ranges that
    are reserved.
    """

    self.assert_raises(certificate(cert_type = 0), 'Ed25519 certificate cannot have a type of 0. This is reserved to avoid conflicts with tor CERTS cells.')
    self.assert_raises(certificate(cert_type = 7), 'Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.')

  def test_truncated_extension(self):
    """
    Include an extension without as much data as it specifies.
    """

    self.assert_raises(certificate(extension_data = [b'']), 'Ed25519 extension is missing header field data')
    self.assert_raises(certificate(extension_data = [b'\x50\x00\x00\x00\x15\x12']), "Ed25519 extension is truncated. It should have 20480 bytes of data but there's only 2.")

  def test_extra_extension_data(self):
    """
    Include an extension with more data than it specifies.
    """

    self.assert_raises(certificate(extension_data = [b'\x00\x01\x00\x00\x15\x12']), "Ed25519 certificate had 1 bytes of unused extension data")

  def test_truncated_signing_key(self):
    """
    Include an extension with an incorrect signing key size.
    """

    self.assert_raises(certificate(extension_data = [b'\x00\x02\x04\x07\11\12']), "Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was 2.")

  def test_validation_with_descriptor_key(self):
    """
    Validate a descriptor signature using the ed25519 master key within the
    descriptor.
    """

    if not stem.prereq._is_pynacl_available():
      test.runner.skip(self, '(requires pynacl module)')
      return

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = False))

    desc.certificate.validate(desc)

  def test_validation_with_embedded_key(self):
    """
    Validate a descriptor signature using the signing key within the ed25519
    certificate.
    """

    if not stem.prereq._is_pynacl_available():
      test.runner.skip(self, '(requires pynacl module)')
      return

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = False))

    desc.ed25519_master_key = None
    desc.certificate.validate(desc)

  def test_validation_with_invalid_descriptor(self):
    """
    Validate a descriptor without a valid signature.
    """

    if not stem.prereq._is_pynacl_available():
      test.runner.skip(self, '(requires pynacl module)')
      return

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = False))

    cert = Ed25519Certificate.parse(certificate())
    self.assertRaisesRegexp(ValueError, re.escape('Ed25519KeyCertificate signing key is invalid (Signature was forged or corrupt)'), cert.validate, desc)


class TestCertificate(unittest.TestCase):
  def test_with_invalid_version(self):
    cert_bytes = b'\x02\x04'
    self.assertRaisesRegexp(ValueError, 'Unknown Certificate version', stem.descriptor.certificate._parse_certificate, cert_bytes, None)

  def test_with_invalid_type(self):
    cert_bytes = b'\x01\x07'
    self.assertRaisesRegexp(ValueError, 'Unknown Certificate type', stem.descriptor.certificate._parse_certificate, cert_bytes, None)

  def test_parse_extensions_truncated_extension(self):
    cert_bytes = b'\x00' * 39  # First 40 bytes are standard fields
    cert_bytes += b'\x01'      # n_extensions = 1
    cert_bytes += b'\x00\x08'  # extension length = 8 bytes
    cert_bytes += b'\x04'      # ext_type = 0x04
    cert_bytes += stem.descriptor.certificate.SIGNATURE_LENGTH * b'\x00'  # pad empty signature block

    self.assertRaisesRegexp(ValueError, 'Certificate contained truncated extension', stem.descriptor.certificate._parse_extensions, cert_bytes)

  def test_parse_extensions_invalid_certificate_extension_type(self):
    cert_bytes = b'\x00' * 39  # First 40 bytes are standard fields
    cert_bytes += b'\x01'      # n_extensions = 1
    cert_bytes += b'\x00\x08'  # extension length = 8 bytes
    cert_bytes += b'\x00' * 6  # pad out to 8 bytes
    cert_bytes += stem.descriptor.certificate.SIGNATURE_LENGTH * b'\x00'  # pad empty signature block

    self.assertRaisesRegexp(ValueError, 'Invalid certificate extension type:', stem.descriptor.certificate._parse_extensions, cert_bytes)

  def test_parse_extensions_invalid_n_extensions_count(self):
    cert_bytes = b'\x00' * 39  # First 40 bytes are standard fields
    cert_bytes += b'\x02'      # n_extensions = 2
    cert_bytes += b'\x00\x08'  # extension length = 8 bytes
    cert_bytes += b'\x04'      # certificate type
    cert_bytes += b'\x00' * 5  # pad out to 8 bytes
    cert_bytes += stem.descriptor.certificate.SIGNATURE_LENGTH * b'\x00'  # pad empty signature block

    self.assertRaisesRegexp(ValueError, 'n_extensions was 2 but parsed 1', stem.descriptor.certificate._parse_extensions, cert_bytes)

  def test_ed25519_key_certificate_without_extensions(self):
    cert_bytes = b'\x01\x04' + b'\x00' * 37  # First 40 bytes are standard fields
    cert_bytes += b'\x00'   # n_extensions = 0
    cert_bytes += stem.descriptor.certificate.SIGNATURE_LENGTH * b'\x00'  # pad empty signature block

    exc_msg = 'Ed25519KeyCertificate missing SignedWithEd25519KeyCertificateExtension extension'
    self.assertRaisesRegexp(ValueError, exc_msg, stem.descriptor.certificate._parse_certificate, cert_bytes, None, validate = True)

  def test_certificate_with_invalid_signature(self):
    if not stem.prereq._is_pynacl_available():
      test.runner.skip(self, '(requires pynacl module)')
      return

    import nacl.signing
    import nacl.encoding

    master_key = nacl.signing.SigningKey.generate()
    master_key_base64 = master_key.encode(nacl.encoding.Base64Encoder)

    cert_bytes = b'\x01\x04' + b'\x00' * 37  # 40 byte preamble of standard fields
    cert_bytes += b'\x01'  # n_extensions = 1
    cert_bytes += b'\x00\x08'  # extentsion length = 8 bytes
    cert_bytes += b'\x04' + b'\x00' * 5  # certificate type + padding out to 8 bytes
    cert_bytes += stem.descriptor.certificate.SIGNATURE_LENGTH * b'\x00'  # empty signature block

    self.assertRaisesRegexp(ValueError, 'Ed25519KeyCertificate signature invalid', stem.descriptor.certificate._parse_certificate, cert_bytes, master_key_base64, validate = True)
