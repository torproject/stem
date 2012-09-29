"""
Unit tests for the KeyCertificate of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import KeyCertificate
from test.mocking import get_key_certificate, CRYPTO_BLOB, KEY_CERTIFICATE_HEADER, KEY_CERTIFICATE_FOOTER

class TestKeyCertificate(unittest.TestCase):
  def test_minimal(self):
    """
    Parses a minimal key certificate.
    """
    
    certificate = get_key_certificate()
    
    self.assertEqual(3, certificate.version)
    self.assertEqual(None, certificate.address)
    self.assertEqual(None, certificate.dir_port)
    self.assertEqual("27B6B5996C426270A5C95488AA5BCEB6BCC86956", certificate.fingerprint)
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
    
    certificate = get_key_certificate({"pepperjack": "is oh so tasty!"})
    self.assertEquals(["pepperjack is oh so tasty!"], certificate.get_unrecognized_lines())
  
  def test_first_and_last_lines(self):
    """
    Includes a non-mandatory field before the 'dir-key-certificate-version'
    line or after the 'dir-key-certification' line.
    """
    
    content = get_key_certificate(content = True)
    
    for cert_text in ("dir-address 127.0.0.1:80\n" + content,
                      content + "\ndir-address 127.0.0.1:80"):
      self.assertRaises(ValueError, KeyCertificate, cert_text)
      
      certificate = KeyCertificate(cert_text, False)
      self.assertEqual("127.0.0.1", certificate.address)
      self.assertEqual(80, certificate.dir_port)
  
  def test_missing_fields(self):
    """
    Parse a key certificate where a mandatory field is missing.
    """
    
    mandatory_fields = [entry[0] for entry in KEY_CERTIFICATE_HEADER + KEY_CERTIFICATE_FOOTER]
    
    for excluded_field in mandatory_fields:
      content = get_key_certificate(exclude = (excluded_field,), content = True)
      self.assertRaises(ValueError, KeyCertificate, content)
      
      certificate = KeyCertificate(content, False)
      
      if excluded_field == "fingerprint":
        self.assertEqual(3, certificate.version)
      else:
        self.assertEqual("27B6B5996C426270A5C95488AA5BCEB6BCC86956", certificate.fingerprint)
  
  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """
    
    certificate = get_key_certificate({"dir-key-published": "2011-11-28 21:51:04\n\n\n"})
    self.assertEqual(datetime.datetime(2011, 11, 28, 21, 51, 4), certificate.published)

