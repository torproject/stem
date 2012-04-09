"""
Unit tests for stem.descriptor.server_descriptor.
"""

import datetime
import StringIO
import unittest

import stem.descriptor.server_descriptor
from stem.descriptor.server_descriptor import RelayDescriptorV3

CRYPTO_BLOB = """
MIGJAoGBAJv5IIWQ+WDWYUdyA/0L8qbIkEVH/cwryZWoIaPAzINfrw1WfNZGtBmg
skFtXhOHHqTRN4GPPrZsAIUOQGzQtGb66IQgT4tO/pj+P6QmSCCdTfhvGfgTCsC+
WPi4Fl2qryzTb3QO5r5x7T8OsG2IBUET1bLQzmtbC560SYR49IvVAgMBAAE=
"""

SAMPLE_DESCRIPTOR_ATTR = (
  ("router", "caerSidi 71.35.133.197 9001 0 0"),
  ("published", "2012-03-01 17:15:27"),
  ("bandwidth", "153600 256000 104590"),
  ("reject", "*:*"),
  ("onion-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
  ("signing-key", "\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----" % CRYPTO_BLOB),
  ("router-signature", "\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----" % CRYPTO_BLOB),
)

def _make_descriptor(attr = None, exclude = None):
  """
  Constructs a minimal server descriptor with the given attributes.
  
  Arguments:
    attr (dict)    - keyword/value mappings to be included in the descriptor
    exclude (list) - mandatory keywords to exclude from the descriptor
  
  Returns:
    str with customized descriptor content
  """
  
  descriptor_lines = []
  if attr == None: attr = {}
  if exclude == None: exclude = []
  
  for keyword, value in SAMPLE_DESCRIPTOR_ATTR:
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

class TestServerDescriptor(unittest.TestCase):
  def test_minimal_descriptor(self):
    """
    Basic sanity check that we can parse a descriptor with minimal attributes.
    """
    
    desc_text = _make_descriptor()
    desc = RelayDescriptorV3(desc_text)
    
    self.assertEquals("caerSidi", desc.nickname)
    self.assertEquals("71.35.133.197", desc.address)
    self.assertEquals(None, desc.fingerprint)
    self.assertTrue(CRYPTO_BLOB in desc.onion_key)
    self.assertTrue(CRYPTO_BLOB in desc.signing_key)
    self.assertTrue(CRYPTO_BLOB in desc.signature)
  
  def test_with_opt(self):
    """
    Includes an 'opt <keyword> <value>' entry.
    """
    
    desc_text = _make_descriptor({"opt": "contact www.atagar.com/contact/"})
    desc = RelayDescriptorV3(desc_text)
    self.assertEquals("www.atagar.com/contact/", desc.contact)
  
  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """
    
    desc_text = _make_descriptor({"pepperjack": "is oh so tasty!"})
    desc = RelayDescriptorV3(desc_text)
    self.assertEquals(["pepperjack is oh so tasty!"], desc.get_unrecognized_lines())
  
  def test_proceeding_line(self):
    """
    Includes a line prior to the 'router' entry.
    """
    
    desc_text = "hibernate 1\n" + _make_descriptor()
    self._expect_invalid_attr(desc_text)
  
  def test_trailing_line(self):
    """
    Includes a line after the 'router-signature' entry.
    """
    
    desc_text = _make_descriptor() + "\nhibernate 1"
    self._expect_invalid_attr(desc_text)
  
  def test_nickname_missing(self):
    """
    Constructs with a malformed router entry.
    """
    
    desc_text = _make_descriptor({"router": " 71.35.133.197 9001 0 0"})
    self._expect_invalid_attr(desc_text, "nickname")
  
  def test_nickname_too_long(self):
    """
    Constructs with a nickname that is an invalid length.
    """
    
    desc_text = _make_descriptor({"router": "saberrider2008ReallyLongNickname 71.35.133.197 9001 0 0"})
    self._expect_invalid_attr(desc_text, "nickname", "saberrider2008ReallyLongNickname")
  
  def test_nickname_invalid_char(self):
    """
    Constructs with an invalid relay nickname.
    """
    
    desc_text = _make_descriptor({"router": "$aberrider2008 71.35.133.197 9001 0 0"})
    self._expect_invalid_attr(desc_text, "nickname", "$aberrider2008")
  
  def test_address_malformed(self):
    """
    Constructs with an invalid ip address.
    """
    
    desc_text = _make_descriptor({"router": "caerSidi 371.35.133.197 9001 0 0"})
    self._expect_invalid_attr(desc_text, "address", "371.35.133.197")
  
  def test_port_too_high(self):
    """
    Constructs with an ORPort that is too large.
    """
    
    desc_text = _make_descriptor({"router": "caerSidi 71.35.133.197 900001 0 0"})
    self._expect_invalid_attr(desc_text, "or_port", 900001)
  
  def test_port_malformed(self):
    """
    Constructs with an ORPort that isn't numeric.
    """
    
    desc_text = _make_descriptor({"router": "caerSidi 71.35.133.197 900a1 0 0"})
    self._expect_invalid_attr(desc_text, "or_port")
  
  def test_port_newline(self):
    """
    Constructs with a newline replacing the ORPort.
    """
    
    desc_text = _make_descriptor({"router": "caerSidi 71.35.133.197 \n 0 0"})
    self._expect_invalid_attr(desc_text, "or_port")
  
  def test_platform_empty(self):
    """
    Constructs with an empty platform entry.
    """
    
    desc_text = _make_descriptor({"platform": ""})
    desc = RelayDescriptorV3(desc_text, validate = False)
    self.assertEquals("", desc.platform)
    
    # does the same but with 'platform ' replaced with 'platform'
    desc_text = desc_text.replace("platform ", "platform")
    desc = RelayDescriptorV3(desc_text, validate = False)
    self.assertEquals("", desc.platform)
  
  def test_protocols_no_circuit_versions(self):
    """
    Constructs with a protocols line without circuit versions.
    """
    
    desc_text = _make_descriptor({"opt": "protocols Link 1 2"})
    self._expect_invalid_attr(desc_text, "circuit_protocols")
  
  def test_published_leap_year(self):
    """
    Constructs with a published entry for a leap year, and when the date is
    invalid.
    """
    
    desc_text = _make_descriptor({"published": "2011-02-29 04:03:19"})
    self._expect_invalid_attr(desc_text, "published")
    
    desc_text = _make_descriptor({"published": "2012-02-29 04:03:19"})
    expected_published = datetime.datetime(2012, 2, 29, 4, 3, 19)
    self.assertEquals(expected_published, RelayDescriptorV3(desc_text).published)
  
  def test_published_no_time(self):
    """
    Constructs with a published entry without a time component.
    """
    
    desc_text = _make_descriptor({"published": "2012-01-01"})
    self._expect_invalid_attr(desc_text, "published")
  
  def test_annotations(self):
    """
    Checks that content before a descriptor are parsed as annotations.
    """
    
    desc_text = "@pepperjack very tasty\n@mushrooms not so much\n"
    desc_text += _make_descriptor()
    desc_text += "\ntrailing text that should be ignored, ho hum"
    
    # running parse_file_v3 should provide an iterator with a single descriptor
    desc_iter = stem.descriptor.server_descriptor.parse_file_v3(StringIO.StringIO(desc_text))
    desc_entries = list(desc_iter)
    self.assertEquals(1, len(desc_entries))
    desc = desc_entries[0]
    
    self.assertEquals("caerSidi", desc.nickname)
    self.assertEquals("@pepperjack very tasty", desc.get_annotation_lines()[0])
    self.assertEquals("@mushrooms not so much", desc.get_annotation_lines()[1])
    self.assertEquals({"@pepperjack": "very tasty", "@mushrooms": "not so much"}, desc.get_annotations())
    self.assertEquals([], desc.get_unrecognized_lines())
  
  def test_duplicate_field(self):
    """
    Constructs with a field appearing twice.
    """
    
    desc_text = _make_descriptor({"<replace>": ""})
    desc_text = desc_text.replace("<replace>", "contact foo\ncontact bar")
    self._expect_invalid_attr(desc_text, "contact", "foo")
  
  def test_missing_required_attr(self):
    """
    Test making a descriptor with a missing required attribute.
    """
    
    for attr in stem.descriptor.server_descriptor.REQUIRED_FIELDS:
      desc_text = _make_descriptor(exclude = [attr])
      self.assertRaises(ValueError, RelayDescriptorV3, desc_text)
      
      # check that we can still construct it without validation
      desc = RelayDescriptorV3(desc_text, validate = False)
      
      # for one of them checks that the corresponding values are None
      if attr == "router":
        self.assertEquals(None, desc.nickname)
        self.assertEquals(None, desc.address)
        self.assertEquals(None, desc.or_port)
        self.assertEquals(None, desc.socks_port)
        self.assertEquals(None, desc.dir_port)
  
  def _expect_invalid_attr(self, desc_text, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to desc_text having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """
    
    self.assertRaises(ValueError, RelayDescriptorV3, desc_text)
    desc = RelayDescriptorV3(desc_text, validate = False)
    
    if attr:
      # check that the invalid attribute matches the expected value when
      # constructed without validation
      
      self.assertEquals(expected_value, getattr(desc, attr))
    else:
      # check a default attribute
      self.assertEquals("caerSidi", desc.nickname)

