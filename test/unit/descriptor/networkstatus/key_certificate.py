"""
Unit tests for the KeyCertificate of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import KeyCertificate

sig_block = """\
-----BEGIN %s-----
MIGJAoGBAJ5itcJRYNEM3Qf1OVWLRkwjqf84oXPc2ZusaJ5zOe7TVvBMra9GNyc0
NM9y6zVkHCAePAjr4KbW/8P1olA6FUE2LV9bozaU1jFf6K8B2OELKs5FUEW+n+ic
GM0x6MhngyXonWOcKt5Gj+mAu5lrno9tpNbPkz2Utr/Pi0nsDhWlAgMBAAE=
-----END %s-----\
"""

RSA_SIG = sig_block % ("RSA PUBLIC KEY", "RSA PUBLIC KEY")
KEY_SIG = sig_block % ("SIGNATURE", "SIGNATURE")

KEY_CERTIFICATE_ATTR = (
  ("dir-key-certificate-version", "3"),
  ("fingerprint", "27B6B5996C426270A5C95488AA5BCEB6BCC86956"),
  ("dir-key-published", "2011-11-28 21:51:04"),
  ("dir-key-expires", "2012-11-28 21:51:04"),
  ("dir-identity-key", "\n" + RSA_SIG),
  ("dir-signing-key", "\n" + RSA_SIG),
  ("dir-key-certification", "\n" + KEY_SIG),
)

def get_key_certificate(attr = None, exclude = None):
  """
  Constructs a minimal key certificate with the given attributes.
  
  :param dict attr: keyword/value mappings to be included in the entry
  :param list exclude: mandatory keywords to exclude from the entry
  
  :returns: str with customized key certificate content
  """
  
  descriptor_lines = []
  if attr is None: attr = {}
  if exclude is None: exclude = []
  attr = dict(attr) # shallow copy since we're destructive
  
  for keyword, value in KEY_CERTIFICATE_ATTR:
    if keyword in exclude: continue
    elif keyword in attr:
      value = attr[keyword]
      del attr[keyword]
    
    descriptor_lines.append("%s %s" % (keyword, value))
  
  # dump in any unused attributes
  for attr_keyword, attr_value in attr.items():
    descriptor_lines.append("%s %s" % (attr_keyword, attr_value))
  
  return "\n".join(descriptor_lines)

class TestKeyCertificate(unittest.TestCase):
  def test_minimal(self):
    """
    Parses a minimal key certificate.
    """
    
    certificate = KeyCertificate(get_key_certificate())
    
    self.assertEqual(3, certificate.version)
    self.assertEqual(None, certificate.address)
    self.assertEqual(None, certificate.dir_port)
    self.assertEqual("27B6B5996C426270A5C95488AA5BCEB6BCC86956", certificate.fingerprint)
    self.assertEqual(RSA_SIG, certificate.identity_key)
    self.assertEqual(datetime.datetime(2011, 11, 28, 21, 51, 4), certificate.published)
    self.assertEqual(datetime.datetime(2012, 11, 28, 21, 51, 4), certificate.expires)
    self.assertEqual(RSA_SIG, certificate.signing_key)
    self.assertEqual(None, certificate.crosscert)
    self.assertEqual(KEY_SIG, certificate.certification)
    self.assertEqual([], certificate.get_unrecognized_lines())

