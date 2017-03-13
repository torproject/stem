"""
Unit tests for stem.descriptor.certificate.
"""

import unittest

import stem.descriptor.certificate
import stem.prereq
import test.runner


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
