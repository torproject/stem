"""
Unit tests for the KeyCertificate of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import KeyCertificate
from test.mocking import get_key_certificate, CRYPTO_BLOB

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

