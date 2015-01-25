"""
Unit tests for the KeyCertificate of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import KeyCertificate

from test.mocking import (
  get_key_certificate,
  CRYPTO_BLOB,
  KEY_CERTIFICATE_HEADER,
  KEY_CERTIFICATE_FOOTER,
)


class TestKeyCertificate(unittest.TestCase):
  def test_minimal(self):
    """
    Parses a minimal key certificate.
    """

    certificate = get_key_certificate()

    self.assertEqual(3, certificate.version)
    self.assertEqual(None, certificate.address)
    self.assertEqual(None, certificate.dir_port)
    self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', certificate.fingerprint)
    self.assertTrue(CRYPTO_BLOB in certificate.identity_key)
    self.assertEqual(datetime.datetime(2011, 11, 28, 21, 51, 4), certificate.published)
    self.assertEqual(datetime.datetime(2012, 11, 28, 21, 51, 4), certificate.expires)
    self.assertTrue(CRYPTO_BLOB in certificate.signing_key)
    self.assertEqual(None, certificate.crosscert)
    self.assertTrue(CRYPTO_BLOB in certificate.certification)
    self.assertEqual([], certificate.get_unrecognized_lines())

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    certificate = get_key_certificate({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], certificate.get_unrecognized_lines())

  def test_first_and_last_lines(self):
    """
    Includes a non-mandatory field before the 'dir-key-certificate-version'
    line or after the 'dir-key-certification' line.
    """

    content = get_key_certificate(content = True)

    for cert_text in (b'dir-address 127.0.0.1:80\n' + content,
                      content + b'\ndir-address 127.0.0.1:80'):
      self.assertRaises(ValueError, KeyCertificate, cert_text, True)

      certificate = KeyCertificate(cert_text, False)
      self.assertEqual('127.0.0.1', certificate.address)
      self.assertEqual(80, certificate.dir_port)

  def test_missing_fields(self):
    """
    Parse a key certificate where a mandatory field is missing.
    """

    mandatory_fields = [entry[0] for entry in KEY_CERTIFICATE_HEADER + KEY_CERTIFICATE_FOOTER]

    for excluded_field in mandatory_fields:
      content = get_key_certificate(exclude = (excluded_field,), content = True)
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)

      if excluded_field == 'fingerprint':
        self.assertEqual(3, certificate.version)
      else:
        self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', certificate.fingerprint)

  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """

    certificate = get_key_certificate({'dir-key-published': '2011-11-28 21:51:04\n\n\n'})
    self.assertEqual(datetime.datetime(2011, 11, 28, 21, 51, 4), certificate.published)

  def test_version(self):
    """
    Parses the dir-key-certificate-version field, including trying to handle a
    different certificate version with the v3 parser.
    """

    certificate = get_key_certificate({'dir-key-certificate-version': '3'})
    self.assertEqual(3, certificate.version)

    content = get_key_certificate({'dir-key-certificate-version': '4'}, content = True)
    self.assertRaises(ValueError, KeyCertificate, content, True)
    self.assertEqual(4, KeyCertificate(content, False).version)

    content = get_key_certificate({'dir-key-certificate-version': 'boo'}, content = True)
    self.assertRaises(ValueError, KeyCertificate, content, True)
    self.assertEqual(None, KeyCertificate(content, False).version)

  def test_dir_address(self):
    """
    Parses the dir-address field.
    """

    certificate = get_key_certificate({'dir-address': '127.0.0.1:80'})
    self.assertEqual('127.0.0.1', certificate.address)
    self.assertEqual(80, certificate.dir_port)

    test_values = (
      (''),
      ('   '),
      ('127.0.0.1'),
      ('127.0.0.1:'),
      ('80'),
      (':80'),
      ('127.0.0.1a:80'),
      ('127.0.0.1:80a'),
    )

    for test_value in test_values:
      content = get_key_certificate({'dir-address': test_value}, content = True)
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)
      self.assertEqual(None, certificate.address)
      self.assertEqual(None, certificate.dir_port)

  def test_fingerprint(self):
    """
    Parses the fingerprint field.
    """

    test_values = (
      '',
      '   ',
      '27B6B5996C426270A5C95488AA5BCEB6BCC8695',
      '27B6B5996C426270A5C95488AA5BCEB6BCC869568',
    )

    for test_value in test_values:
      content = get_key_certificate({'fingerprint': test_value}, content = True)
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)
      self.assertEqual(None, certificate.fingerprint)

  def test_time_fields(self):
    """
    Parses the dir-key-published and dir-key-expires fields, which both have
    datetime content.
    """

    test_values = (
      '',
      '   ',
      '2012-12-12',
      '2012-12-12 01:01:',
      '2012-12-12 01:a1:01',
    )

    for field, attr in (('dir-key-published', 'published'), ('dir-key-expires', 'expires')):
      for test_value in test_values:
        content = get_key_certificate({field: test_value}, content = True)
        self.assertRaises(ValueError, KeyCertificate, content, True)

        certificate = KeyCertificate(content, False)
        self.assertEqual(None, getattr(certificate, attr))

  def test_key_blocks(self):
    """
    Parses the dir-identity-key, dir-signing-key, dir-key-crosscert, and
    dir-key-certification fields which all just have signature content.
    """

    # the only non-mandatory field that we haven't exercised yet is dir-key-crosscert

    certificate = get_key_certificate({'dir-key-crosscert': '\n-----BEGIN ID SIGNATURE-----%s-----END ID SIGNATURE-----' % CRYPTO_BLOB})
    self.assertTrue(CRYPTO_BLOB in certificate.crosscert)

    test_value = '\n-----BEGIN ID SIGNATURE-----%s-----END UGABUGA SIGNATURE-----' % CRYPTO_BLOB

    for field, attr in (('dir-identity-key', 'identity_key'),
                        ('dir-signing-key', 'signing_key'),
                        ('dir-key-crosscert', 'crosscert'),
                        ('dir-key-certification', 'certification')):
      content = get_key_certificate({field: test_value}, content = True)
      self.assertRaises(ValueError, KeyCertificate, content, True)

      certificate = KeyCertificate(content, False)
      self.assertEqual(None, getattr(certificate, attr))

  def test_wrong_block_type(self):
    """
    Checks that we validate the type of crypto content we receive.
    """

    content = get_key_certificate({'dir-identity-key': '\n-----BEGIN MD5SUM-----%s-----END MD5SUM-----' % CRYPTO_BLOB}, content = True)
    self.assertRaises(ValueError, KeyCertificate, content, True)
