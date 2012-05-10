"""
Unit tests for stem.descriptor.extrainfo_descriptor.
"""

import unittest
from stem.descriptor.extrainfo_descriptor import ExtraInfoDescriptor

CRYPTO_BLOB = """
K5FSywk7qvw/boA4DQcqkls6Ize5vcBYfhQ8JnOeRQC9+uDxbnpm3qaYN9jZ8myj
k0d2aofcVbHr4fPQOSST0LXDrhFl5Fqo5um296zpJGvRUeO6S44U/EfJAGShtqWw
7LZqklu+gVvhMKREpchVqlAwXkWR44VENm24Hs+mT3M=
"""

EXTRAINFO_DESCRIPTOR_ATTR = (
  ("extra-info", "ninja B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48"),
  ("published", "2012-05-05 17:03:50"),
  ("router-signature", "\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB),
)

def _make_descriptor(attr = None, exclude = None):
  """
  Constructs a minimal extrainfo descriptor with the given attributes.
  
  Arguments:
    attr (dict)     - keyword/value mappings to be included in the descriptor
    exclude (list)  - mandatory keywords to exclude from the descriptor
  
  Returns:
    str with customized descriptor content
  """
  
  descriptor_lines = []
  if attr is None: attr = {}
  if exclude is None: exclude = []
  attr = dict(attr) # shallow copy since we're destructive
  
  for keyword, value in EXTRAINFO_DESCRIPTOR_ATTR:
    if keyword in exclude: continue
    elif keyword in attr:
      value = attr[keyword]
      del attr[keyword]
    
    # if this is the last entry then we should dump in any unused attributes
    if keyword == "router-signature":
      for attr_keyword, attr_value in attr.items():
        descriptor_lines.append("%s %s" % (attr_keyword, attr_value))
    
    descriptor_lines.append("%s %s" % (keyword, value))
  
  return "\n".join(descriptor_lines)

class TestExtraInfoDescriptor(unittest.TestCase):
  def test_minimal_extrainfo_descriptor(self):
    """
    Basic sanity check that we can parse an extrainfo descriptor with minimal
    attributes.
    """
    
    desc_text = _make_descriptor()
    desc = ExtraInfoDescriptor(desc_text)
    
    self.assertEquals("ninja", desc.nickname)
    self.assertEquals("B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48", desc.fingerprint)
    self.assertTrue(CRYPTO_BLOB in desc.signature)
  
  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """
    
    desc_text = _make_descriptor({"pepperjack": "is oh so tasty!"})
    desc = ExtraInfoDescriptor(desc_text)
    self.assertEquals(["pepperjack is oh so tasty!"], desc.get_unrecognized_lines())
  
  def test_proceeding_line(self):
    """
    Includes a line prior to the 'extra-info' entry.
    """
    
    desc_text = "exit-streams-opened port=80\n" + _make_descriptor()
    self._expect_invalid_attr(desc_text)
  
  def test_trailing_line(self):
    """
    Includes a line after the 'router-signature' entry.
    """
    
    desc_text = _make_descriptor() + "\nexit-streams-opened port=80"
    self._expect_invalid_attr(desc_text)
  
  def test_extrainfo_line_missing_fields(self):
    """
    Checks that validation catches when the extra-info line is missing fields
    and that without validation both the nickname and fingerprint are left as
    None.
    """
    
    test_entry = (
      "ninja",
      "ninja ",
      "B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48",
      " B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48",
    )
    
    for entry in test_entry:
      desc_text = _make_descriptor({"extra-info": entry})
      desc = self._expect_invalid_attr(desc_text, "nickname")
      self.assertEquals(None, desc.nickname)
      self.assertEquals(None, desc.fingerprint)
  
  def test_geoip_db_digest(self):
    """
    Parses a geoip-db-digest line with valid data.
    """
    
    geoip_db_digest = "916A3CA8B7DF61473D5AE5B21711F35F301CE9E8"
    desc_text = _make_descriptor({"geoip-db-digest": geoip_db_digest})
    desc = ExtraInfoDescriptor(desc_text)
    self.assertEquals(geoip_db_digest, desc.geoip_db_digest)
  
  def test_geoip_db_digest_invalid(self):
    """
    Parses the geoip-db-digest line with a variety of bad input.
    """
    
    test_entry = (
      "",
      "916A3CA8B7DF61473D5AE5B21711F35F301CE9E",
      "916A3CA8B7DF61473D5AE5B21711F35F301CE9E88",
      "916A3CA8B7DF61473D5AE5B21711F35F301CE9EG",
      "916A3CA8B7DF61473D5AE5B21711F35F301CE9E-",
    )
    
    for entry in test_entry:
      desc_text = _make_descriptor({"geoip-db-digest": entry})
      desc = self._expect_invalid_attr(desc_text, "geoip_db_digest", entry)
  
  def _expect_invalid_attr(self, desc_text, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to desc_text having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """
    
    self.assertRaises(ValueError, ExtraInfoDescriptor, desc_text)
    desc = ExtraInfoDescriptor(desc_text, validate = False)
    
    if attr:
      # check that the invalid attribute matches the expected value when
      # constructed without validation
      
      self.assertEquals(expected_value, getattr(desc, attr))
    else:
      # check a default attribute
      self.assertEquals("ninja", desc.nickname)
    
    return desc

