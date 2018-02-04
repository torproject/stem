"""
Unit tests for stem.client.Certificate.
"""

import unittest

from stem.client.datatype import CertType, Certificate


class TestCertificate(unittest.TestCase):
  def test_constructor(self):
    test_data = (
      ((1, '\x7f\x00\x00\x01'), (CertType.LINK, 1, '\x7f\x00\x00\x01')),
      ((2, '\x7f\x00\x00\x01'), (CertType.IDENTITY, 2, '\x7f\x00\x00\x01')),
      ((3, '\x7f\x00\x00\x01'), (CertType.AUTHENTICATE, 3, '\x7f\x00\x00\x01')),
      ((4, '\x7f\x00\x00\x01'), (CertType.UNKNOWN, 4, '\x7f\x00\x00\x01')),
      ((CertType.IDENTITY, '\x7f\x00\x00\x01'), (CertType.IDENTITY, 2, '\x7f\x00\x00\x01')),
    )

    for (cert_type, cert_value), (expected_type, expected_type_int, expected_value) in test_data:
      cert = Certificate(cert_type, cert_value)
      self.assertEqual(expected_type, cert.type)
      self.assertEqual(expected_type_int, cert.type_int)
      self.assertEqual(expected_value, cert.value)

  def test_unknown_type(self):
    cert = Certificate(12, 'hello')
    self.assertEqual(CertType.UNKNOWN, cert.type)
    self.assertEqual(12, cert.type_int)
    self.assertEqual('hello', cert.value)

  def test_packing(self):
    cert, content = Certificate.pop('\x02\x00\x04\x00\x00\x01\x01\x04\x04aq\x0f\x02\x00\x00\x00\x00')
    self.assertEqual('\x04\x04aq\x0f\x02\x00\x00\x00\x00', content)

    self.assertEqual(CertType.IDENTITY, cert.type)
    self.assertEqual(2, cert.type_int)
    self.assertEqual('\x00\x00\x01\x01', cert.value)
    self.assertEqual('\x02\x00\x04\x00\x00\x01\x01', cert.pack())
