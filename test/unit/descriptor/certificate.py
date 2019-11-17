"""
Unit tests for stem.descriptor.certificate.
"""

import base64
import datetime
import re
import unittest

import stem.descriptor.certificate
import stem.util.str_tools
import stem.prereq
import test.require

from stem.client.datatype import Size, CertType
from stem.descriptor.certificate import ED25519_SIGNATURE_LENGTH, ExtensionType, Ed25519Certificate, Ed25519CertificateV1, Ed25519Extension
from test.unit.descriptor import get_resource

ED25519_CERT = """
AQQABhtZAaW2GoBED1IjY3A6f6GNqBEl5A83fD2Za9upGke51JGqAQAgBABnprVR
ptIr43bWPo2fIzo3uOywfoMrryprpbm4HhCkZMaO064LP+1KNuLvlc8sGG8lTjx1
g4k3ELuWYgHYWU5rAia7nl4gUfBZOEfHAfKES7l3d63dBEjEX98Ljhdp2w4=
""".strip()

EXPECTED_CERT_KEY = b'\xa5\xb6\x1a\x80D\x0fR#cp:\x7f\xa1\x8d\xa8\x11%\xe4\x0f7|=\x99k\xdb\xa9\x1aG\xb9\xd4\x91\xaa'
EXPECTED_EXTENSION_DATA = b'g\xa6\xb5Q\xa6\xd2+\xe3v\xd6>\x8d\x9f#:7\xb8\xec\xb0~\x83+\xaf*k\xa5\xb9\xb8\x1e\x10\xa4d'
EXPECTED_SIGNATURE = b'\xc6\x8e\xd3\xae\x0b?\xedJ6\xe2\xef\x95\xcf,\x18o%N<u\x83\x897\x10\xbb\x96b\x01\xd8YNk\x02&\xbb\x9e^ Q\xf0Y8G\xc7\x01\xf2\x84K\xb9ww\xad\xdd\x04H\xc4_\xdf\x0b\x8e\x17i\xdb\x0e'


def certificate(version = 1, cert_type = 4, extension_data = []):
  """
  Provides base64 encoded Ed25519 certifificate content.

  :param int version: certificate version
  :param int cert_type: certificate type
  :param list extension_data: extensions to embed within the certificate
  """

  return base64.b64encode(b''.join([
    stem.util.str_tools._to_bytes(chr(version)),
    stem.util.str_tools._to_bytes(chr(cert_type)),
    b'\x00' * 4,               # expiration date, leaving this as the epoch
    b'\x01',                   # key type
    b'\x03' * 32,              # key
    stem.util.str_tools._to_bytes(chr(len(extension_data))),  # extension count
    b''.join(extension_data),
    b'\x01' * ED25519_SIGNATURE_LENGTH]))


class TestEd25519Certificate(unittest.TestCase):
  def test_basic_parsing(self):
    """
    Parse a basic test certificate.
    """

    signing_key = b'\x11' * 32
    cert_bytes = certificate(extension_data = [b'\x00\x20\x04\x07' + signing_key, b'\x00\x00\x05\x04'])
    cert = Ed25519Certificate.from_base64(cert_bytes)

    self.assertEqual(Ed25519CertificateV1, type(cert))
    self.assertEqual(1, cert.version)
    self.assertEqual(stem.util.str_tools._to_unicode(cert_bytes), cert.encoded)
    self.assertEqual(CertType.ED25519_SIGNING, cert.type)
    self.assertEqual(datetime.datetime(1970, 1, 1, 0, 0), cert.expiration)
    self.assertEqual(1, cert.key_type)
    self.assertEqual(b'\x03' * 32, cert.key)
    self.assertEqual(b'\x01' * ED25519_SIGNATURE_LENGTH, cert.signature)

    self.assertEqual([
      Ed25519Extension(ExtensionType.HAS_SIGNING_KEY, 7, signing_key),
      Ed25519Extension(5, 4, b''),
    ], cert.extensions)

    self.assertEqual(ExtensionType.HAS_SIGNING_KEY, cert.extensions[0].type)
    self.assertTrue(cert.is_expired())

  def test_with_real_cert(self):
    """
    Parse a certificate from a real server descriptor.
    """

    cert = Ed25519Certificate.from_base64(ED25519_CERT)

    self.assertEqual(Ed25519CertificateV1, type(cert))
    self.assertEqual(1, cert.version)
    self.assertEqual(ED25519_CERT, cert.encoded)
    self.assertEqual(CertType.ED25519_SIGNING, cert.type)
    self.assertEqual(datetime.datetime(2015, 8, 28, 17, 0), cert.expiration)
    self.assertEqual(1, cert.key_type)
    self.assertEqual(EXPECTED_CERT_KEY, cert.key)
    self.assertEqual([Ed25519Extension(4, 0, EXPECTED_EXTENSION_DATA)], cert.extensions)
    self.assertEqual(EXPECTED_SIGNATURE, cert.signature)

  def test_extension_encoding(self):
    """
    Pack an extension back into what we read.
    """

    extension = Ed25519Certificate.from_base64(ED25519_CERT).extensions[0]
    expected = Size.SHORT.pack(len(EXPECTED_EXTENSION_DATA)) + Size.CHAR.pack(4) + Size.CHAR.pack(0) + EXPECTED_EXTENSION_DATA

    self.assertEqual(4, extension.type)
    self.assertEqual(0, extension.flag_int)
    self.assertEqual(EXPECTED_EXTENSION_DATA, extension.data)
    self.assertEqual(expected, extension.pack())

  def test_certificate_encoding(self):
    """
    Pack a certificate back into what we read.
    """

    cert = Ed25519Certificate.from_base64(ED25519_CERT)
    self.assertEqual(ED25519_CERT, cert.encoded)  # read base64 encoding (getting removed in stem 2.x)
    self.assertEqual(ED25519_CERT, cert.to_base64())  # computed base64 encoding

  def test_non_base64(self):
    """
    Parse data that isn't base64 encoded.
    """

    exc_msg = re.escape("Ed25519 certificate wasn't propoerly base64 encoded (Incorrect padding):")
    self.assertRaisesRegexp(ValueError, exc_msg, Ed25519Certificate.from_base64, '\x02\x0323\x04')

  def test_too_short(self):
    """
    Parse data that's too short to be a valid certificate.
    """

    exc_msg = "Ed25519 certificate wasn't propoerly base64 encoded (empty):"
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, '')

    exc_msg = 'Ed25519 certificate was 18 bytes, but should be at least 104'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, 'AQQABhtZAaW2GoBED1IjY3A6')

  def test_with_invalid_version(self):
    """
    We cannot support other certificate versions until they're documented.
    Assert we raise if we don't handle a cert version yet.
    """

    exc_msg = 'Ed25519 certificate is version 2. Parser presently only supports version 1.'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(version = 2))

  def test_with_invalid_cert_type(self):
    """
    Provide an invalid certificate version. Tor specifies a couple ranges that
    are reserved.
    """

    exc_msg = 'Ed25519 certificate type 0 is unrecognized'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(cert_type = 0))

    exc_msg = 'Ed25519 certificate cannot have a type of 1. This is reserved for CERTS cells.'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(cert_type = 1))

    exc_msg = 'Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(cert_type = 7))

  def test_truncated_extension(self):
    """
    Include an extension without as much data as it specifies.
    """

    exc_msg = 'Ed25519 extension is missing header fields'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(extension_data = [b'']))

    exc_msg = "Ed25519 extension is truncated. It should have 20480 bytes of data but there's only 2."
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(extension_data = [b'\x50\x00\x00\x00\x15\x12']))

  def test_extra_extension_data(self):
    """
    Include an extension with more data than it specifies.
    """

    exc_msg = 'Ed25519 certificate had 1 bytes of unused extension data'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(extension_data = [b'\x00\x01\x00\x00\x15\x12']))

  def test_truncated_signing_key(self):
    """
    Include an extension with an incorrect signing key size.
    """

    exc_msg = 'Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was 2.'
    self.assertRaisesWith(ValueError, exc_msg, Ed25519Certificate.from_base64, certificate(extension_data = [b'\x00\x02\x04\x07\11\12']))

  @test.require.ed25519_support
  def test_validation_with_descriptor_key(self):
    """
    Validate a descriptor signature using the ed25519 master key within the
    descriptor.
    """

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = False))

    desc.certificate.validate(desc)

  @test.require.ed25519_support
  def test_validation_with_embedded_key(self):
    """
    Validate a descriptor signature using the signing key within the ed25519
    certificate.
    """

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = False))

    desc.ed25519_master_key = None
    desc.certificate.validate(desc)

  @test.require.ed25519_support
  def test_validation_with_invalid_descriptor(self):
    """
    Validate a descriptor without a valid signature.
    """

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = False))

    cert = Ed25519Certificate.from_base64(certificate())
    self.assertRaisesWith(ValueError, 'Ed25519KeyCertificate signing key is invalid (signature forged or corrupt)', cert.validate, desc)
