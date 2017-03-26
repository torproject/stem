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

from stem.descriptor.certificate import ED25519_SIGNATURE_LENGTH, CertType, Ed25519Certificate, Ed25519CertificateV1

ED25519_CERT = """
AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABnprVR
ptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8sGG8lTjx1
g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98Ljhdp2w4=
""".strip()


def certificate(version = 1, cert_type = 4):
  return base64.b64encode(''.join([
    chr(version),
    chr(cert_type),
    b'\x00' * 4,   # expiration date, leaving this as the epoch
    b'\x01',       # key type
    b'\x03' * 32,  # key
    b'\x00' + b'\x00' * ED25519_SIGNATURE_LENGTH]))


class TestEd25519Certificate(unittest.TestCase):
  def assert_raises(self, parse_arg, exc_msg):
    self.assertRaisesRegexp(ValueError, re.escape(exc_msg), Ed25519Certificate.parse, parse_arg)

  def test_basic_parsing(self):
    cert_bytes = certificate()
    cert = Ed25519Certificate.parse(cert_bytes)

    self.assertEqual(Ed25519CertificateV1, type(cert))
    self.assertEqual(1, cert.version)
    self.assertEqual(cert_bytes, cert.encoded)
    self.assertEqual(CertType.SIGNING, cert.cert_type)
    self.assertEqual(datetime.datetime(1970, 1, 1, 1, 0), cert.expiration)
    self.assertEqual(1, cert.key_type)
    self.assertEqual(b'\x03' * 32, cert.key)

  def test_with_real_cert(self):
    cert = Ed25519Certificate.parse(ED25519_CERT)

    self.assertEqual(Ed25519CertificateV1, type(cert))
    self.assertEqual(1, cert.version)
    self.assertEqual(ED25519_CERT, cert.encoded)
    self.assertEqual(CertType.SIGNING, cert.cert_type)
    self.assertEqual(datetime.datetime(2015, 8, 28, 19, 0), cert.expiration)
    self.assertEqual(1, cert.key_type)
    self.assertEqual('\xa5\xb6\x1a\x80D\x0fR#cp:\x7f\xa1\x8d\xa8\x11%\xe4\x0f7|=\x99k\xdb\xa9\x1aG\xb9\xd4\x91\xaa', cert.key)

  def test_non_base64(self):
    self.assert_raises('\x02\x0323\x04', "Ed25519 certificate wasn't propoerly base64 encoded (Incorrect padding):")

  def test_too_short(self):
    self.assert_raises('', "Ed25519 certificate wasn't propoerly base64 encoded (empty):")
    self.assert_raises('AQQABhtZAaW2GoBED1IjY3A6', 'Ed25519 certificate was 18 bytes, but should be at least 104')

  def test_with_invalid_version(self):
    self.assert_raises(certificate(version = 2), 'Ed25519 certificate is version 2. Parser presently only supports version 1.')

  def test_with_invalid_cert_type(self):
    self.assert_raises(certificate(cert_type = 0), 'Ed25519 certificate cannot have a type of 0. This is reserved to avoid conflicts with tor CERTS cells.')
    self.assert_raises(certificate(cert_type = 7), 'Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.')






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
