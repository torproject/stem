"""
Unit tests for the RouterStatusEntry of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor import Flag
from stem.descriptor.networkstatus import RouterStatusEntry, _decode_fingerprint
from stem.version import Version
from stem.exit_policy import MicrodescriptorExitPolicy

ROUTER_STATUS_ENTRY_ATTR = (
  ("r", "caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0"),
  ("s", "Fast Named Running Stable Valid"),
)

def get_router_status_entry(attr = None, exclude = None):
  """
  Constructs a minimal router status entry with the given attributes.
  
  :param dict attr: keyword/value mappings to be included in the entry
  :param list exclude: mandatory keywords to exclude from the entry
  
  :returns: str with customized router status entry content
  """
  
  descriptor_lines = []
  if attr is None: attr = {}
  if exclude is None: exclude = []
  attr = dict(attr) # shallow copy since we're destructive
  
  for keyword, value in ROUTER_STATUS_ENTRY_ATTR:
    if keyword in exclude: continue
    elif keyword in attr:
      value = attr[keyword]
      del attr[keyword]
    
    descriptor_lines.append("%s %s" % (keyword, value))
  
  # dump in any unused attributes
  for attr_keyword, attr_value in attr.items():
    descriptor_lines.append("%s %s" % (attr_keyword, attr_value))
  
  return "\n".join(descriptor_lines)

class TestRouterStatusEntry(unittest.TestCase):
  def test_fingerprint_decoding(self):
    """
    Tests for the _decode_fingerprint() helper.
    """
    
    # consensus identity field and fingerprint for caerSidi and Amunet1-5
    test_values = {
      'p1aag7VwarGxqctS7/fS0y5FU+s': 'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB',
      'IbhGa8T+8tyy/MhxCk/qI+EI2LU': '21B8466BC4FEF2DCB2FCC8710A4FEA23E108D8B5',
      '20wYcbFGwFfMktmuffYj6Z1RM9k': 'DB4C1871B146C057CC92D9AE7DF623E99D5133D9',
      'nTv9AG1cZeFW2hXiSIEAF6JLRJ4': '9D3BFD006D5C65E156DA15E248810017A24B449E',
      '/UKsQiOSGPi/6es0/ha1prNTeDI': 'FD42AC42239218F8BFE9EB34FE16B5A6B3537832',
      '/nHdqoKZ6bKZixxAPzYt9Qen+Is': 'FE71DDAA8299E9B2998B1C403F362DF507A7F88B',
    }
    
    for arg, expected in test_values.items():
      self.assertEqual(expected, _decode_fingerprint(arg, True))
    
    # checks with some malformed inputs
    for arg in ('', '20wYcb', '20wYcb' * 30):
      self.assertRaises(ValueError, _decode_fingerprint, arg, True)
      self.assertEqual(None, _decode_fingerprint(arg, False))
  
  def test_minimal(self):
    """
    Parses a minimal router status entry.
    """
    
    entry = RouterStatusEntry(get_router_status_entry())
    
    expected_flags = set([Flag.FAST, Flag.NAMED, Flag.RUNNING, Flag.STABLE, Flag.VALID])
    self.assertEqual(None, entry.document)
    self.assertEqual("caerSidi", entry.nickname)
    self.assertEqual("A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB", entry.fingerprint)
    self.assertEqual("oQZFLYe9e4A7bOkWKR7TaNxb0JE", entry.digest)
    self.assertEqual(datetime.datetime(2012, 8, 6, 11, 19, 31), entry.published)
    self.assertEqual("71.35.150.29", entry.address)
    self.assertEqual(9001, entry.or_port)
    self.assertEqual(None, entry.dir_port)
    self.assertEqual(expected_flags, set(entry.flags))
    self.assertEqual(None, entry.version_line)
    self.assertEqual(None, entry.version)
    self.assertEqual(None, entry.bandwidth)
    self.assertEqual(None, entry.measured)
    self.assertEqual([], entry.unrecognized_bandwidth_entries)
    self.assertEqual(None, entry.exit_policy)
    self.assertEqual(None, entry.microdescriptor_hashes)
    self.assertEqual([], entry.get_unrecognized_lines())
  
  def test_missing_fields(self):
    """
    Parses a router status entry that's missing fields.
    """
    
    content = get_router_status_entry(exclude = ('r', 's'))
    self._expect_invalid_attr(content, "address")
    
    content = get_router_status_entry(exclude = ('r',))
    self._expect_invalid_attr(content, "address")
    
    content = get_router_status_entry(exclude = ('s',))
    self._expect_invalid_attr(content, "flags")
  
  def test_unrecognized_lines(self):
    """
    Parses a router status entry with new keywords.
    """
    
    content = get_router_status_entry({'z': 'New tor feature: sparkly unicorns!'})
    entry = RouterStatusEntry(content)
    self.assertEquals(['z New tor feature: sparkly unicorns!'], entry.get_unrecognized_lines())
  
  def test_proceeding_line(self):
    """
    Includes content prior to the 'r' line.
    """
    
    content = 'z some stuff\n' + get_router_status_entry()
    self._expect_invalid_attr(content, "_unrecognized_lines", ['z some stuff'])
  
  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """
    
    content = get_router_status_entry() + "\n\nv Tor 0.2.2.35\n\n"
    entry = RouterStatusEntry(content)
    self.assertEqual("Tor 0.2.2.35", entry.version_line)
  
  def test_missing_r_field(self):
    """
    Excludes fields from the 'r' line.
    """
    
    components = (
      ('nickname', 'caerSidi'),
      ('fingerprint', 'p1aag7VwarGxqctS7/fS0y5FU+s'),
      ('digest', 'oQZFLYe9e4A7bOkWKR7TaNxb0JE'),
      ('published', '2012-08-06 11:19:31'),
      ('address', '71.35.150.29'),
      ('or_port', '9001'),
      ('dir_port', '0'),
    )
    
    for attr, value in components:
      # construct the 'r' line without this field
      test_components = [comp[1] for comp in components]
      test_components.remove(value)
      r_line = ' '.join(test_components)
      
      content = get_router_status_entry({'r': r_line})
      self._expect_invalid_attr(content, attr)
  
  def test_malformed_nickname(self):
    """
    Parses an 'r' line with a malformed nickname.
    """
    
    test_values = (
      "",
      "saberrider2008ReallyLongNickname", # too long
      "$aberrider2008", # invalid characters
    )
    
    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_ATTR[0][1].replace("caerSidi", value)
      content = get_router_status_entry({'r': r_line})
      
      # TODO: Initial whitespace is consumed as part of the keyword/value
      # divider. This is a bug in the case of V3 router status entries, but
      # proper behavior for V2 router status entries and server/extrainfo
      # descriptors.
      #
      # I'm inclined to leave this as-is for the moment since fixing it
      # requires special KEYWORD_LINE handling, and the only result of this bug
      # is that our validation doesn't catch the new SP restriction on V3
      # entries.
      
      if value == "": value = None
      
      self._expect_invalid_attr(content, "nickname", value)
  
  def test_malformed_fingerprint(self):
    """
    Parses an 'r' line with a malformed fingerprint.
    """
    
    test_values = (
      "",
      "zzzzz",
      "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
    )
    
    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_ATTR[0][1].replace("p1aag7VwarGxqctS7/fS0y5FU+s", value)
      content = get_router_status_entry({'r': r_line})
      self._expect_invalid_attr(content, "fingerprint")
  
  def test_malformed_published_date(self):
    """
    Parses an 'r' line with a malformed published date.
    """
    
    test_values = (
      "",
      "2012-08-06 11:19:",
      "2012-08-06 11:19:71",
      "2012-08-06 11::31",
      "2012-08-06 11:79:31",
      "2012-08-06 :19:31",
      "2012-08-06 41:19:31",
      "2012-08- 11:19:31",
      "2012-08-86 11:19:31",
      "2012--06 11:19:31",
      "2012-38-06 11:19:31",
      "-08-06 11:19:31",
      "2012-08-06   11:19:31",
    )
    
    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_ATTR[0][1].replace("2012-08-06 11:19:31", value)
      content = get_router_status_entry({'r': r_line})
      self._expect_invalid_attr(content, "published")
  
  def test_malformed_address(self):
    """
    Parses an 'r' line with a malformed address.
    """
    
    test_values = (
      "",
      "71.35.150.",
      "71.35..29",
      "71.35.150",
      "71.35.150.256",
    )
    
    for value in test_values:
      r_line = ROUTER_STATUS_ENTRY_ATTR[0][1].replace("71.35.150.29", value)
      content = get_router_status_entry({'r': r_line})
      self._expect_invalid_attr(content, "address", value)
  
  def test_malformed_port(self):
    """
    Parses an 'r' line with a malformed ORPort or DirPort.
    """
    
    test_values = (
      "",
      "-1",
      "399482",
      "blarg",
    )
    
    for value in test_values:
      for include_or_port in (False, True):
        for include_dir_port in (False, True):
          if not include_or_port and not include_dir_port:
            continue
          
          r_line = ROUTER_STATUS_ENTRY_ATTR[0][1]
          
          if include_or_port:
            r_line = r_line.replace(" 9001 ", " %s " % value)
          
          if include_dir_port:
            r_line = r_line[:-1] + value
          
          attr = "or_port" if include_or_port else "dir_port"
          expected = int(value) if value.isdigit() else None
          
          content = get_router_status_entry({'r': r_line})
          self._expect_invalid_attr(content, attr, expected)
  
  def test_flags(self):
    """
    Handles a variety of flag inputs.
    """
    
    test_values = {
      "": [],
      "Fast": [Flag.FAST],
      "Fast Valid": [Flag.FAST, Flag.VALID],
      "Ugabuga": ["Ugabuga"],
    }
    
    for s_line, expected in test_values.items():
      content = get_router_status_entry({'s': s_line})
      entry = RouterStatusEntry(content)
      self.assertEquals(expected, entry.flags)
    
    # tries some invalid inputs
    test_values = {
      "Fast   ": [Flag.FAST, "", "", ""],
      "Fast  Valid": [Flag.FAST, "", Flag.VALID],
      "Fast Fast": [Flag.FAST, Flag.FAST],
    }
    
    for s_line, expected in test_values.items():
      content = get_router_status_entry({'s': s_line})
      self._expect_invalid_attr(content, "flags", expected)
  
  def test_versions(self):
    """
    Handles a variety of version inputs.
    """
    
    test_values = {
      "Tor 0.2.2.35": Version("0.2.2.35"),
      "Tor 0.1.2": Version("0.1.2"),
      "Torr new_stuff": None,
      "new_stuff and stuff": None,
    }
    
    for v_line, expected in test_values.items():
      content = get_router_status_entry({'v': v_line})
      entry = RouterStatusEntry(content)
      self.assertEquals(expected, entry.version)
      self.assertEquals(v_line, entry.version_line)
    
    # tries an invalid input
    content = get_router_status_entry({'v': "Tor ugabuga"})
    self._expect_invalid_attr(content, "version")
  
  def test_bandwidth(self):
    """
    Handles a variety of 'w' lines.
    """
    
    test_values = {
      "Bandwidth=0": (0, None, []),
      "Bandwidth=63138": (63138, None, []),
      "Bandwidth=11111 Measured=482": (11111, 482, []),
      "Bandwidth=11111 Measured=482 Blarg!": (11111, 482, ["Blarg!"]),
    }
    
    for w_line, expected in test_values.items():
      content = get_router_status_entry({'w': w_line})
      entry = RouterStatusEntry(content)
      self.assertEquals(expected[0], entry.bandwidth)
      self.assertEquals(expected[1], entry.measured)
      self.assertEquals(expected[2], entry.unrecognized_bandwidth_entries)
    
    # tries some invalid inputs
    test_values = (
      "",
      "blarg",
      "Bandwidth",
      "Bandwidth=",
      "Bandwidth:0",
      "Bandwidth 0",
      "Bandwidth=-10",
      "Bandwidth=10 Measured",
      "Bandwidth=10 Measured=",
      "Bandwidth=10 Measured=-50",
    )
    
    for w_line in test_values:
      content = get_router_status_entry({'w': w_line})
      self._expect_invalid_attr(content)
  
  def test_exit_policy(self):
    """
    Handles a variety of 'p' lines.
    """
    
    test_values = {
      "reject 1-65535": MicrodescriptorExitPolicy("reject 1-65535"),
      "accept 80,110,143,443": MicrodescriptorExitPolicy("accept 80,110,143,443"),
    }
    
    for p_line, expected in test_values.items():
      content = get_router_status_entry({'p': p_line})
      entry = RouterStatusEntry(content)
      self.assertEquals(expected, entry.exit_policy)
    
    # tries some invalid inputs
    test_values = (
      "",
      "blarg",
      "reject -50",
      "accept 80,",
    )
    
    for p_line in test_values:
      content = get_router_status_entry({'p': p_line})
      self._expect_invalid_attr(content, "exit_policy")
  
  def test_microdescriptor_hashes(self):
    """
    Handles a variety of 'm' lines.
    """
    
    test_values = {
      "8,9,10,11,12":
        [([8, 9, 10, 11, 12], {})],
      "8,9,10,11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs":
        [([8, 9, 10, 11, 12], {"sha256": "g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs"})],
      "8,9,10,11,12 sha256=g1vx9si329muxV md5=3tquWIXXySNOIwRGMeAESKs/v4DWs":
        [([8, 9, 10, 11, 12], {"sha256": "g1vx9si329muxV", "md5": "3tquWIXXySNOIwRGMeAESKs/v4DWs"})],
    }
    
    # we need a document that's a vote
    mock_document = lambda x: x # just need anything with a __dict__
    mock_document.__dict__["is_vote"] = True
    mock_document.__dict__["is_consensus"] = False
    
    for m_line, expected in test_values.items():
      content = get_router_status_entry({'m': m_line})
      entry = RouterStatusEntry(content, document = mock_document)
      self.assertEquals(expected, entry.microdescriptor_hashes)
    
    # try without a document
    content = get_router_status_entry({'m': "8,9,10,11,12"})
    self._expect_invalid_attr(content, "microdescriptor_hashes")
    
    # tries some invalid inputs
    test_values = (
      "",
      "4,a,2",
      "1,2,3 stuff",
    )
    
    for m_line in test_values:
      content = get_router_status_entry({'m': m_line})
      self.assertRaises(ValueError, RouterStatusEntry, content, True, mock_document)
  
  def _expect_invalid_attr(self, content, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to content having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """
    
    self.assertRaises(ValueError, RouterStatusEntry, content)
    entry = RouterStatusEntry(content, False)
    
    if attr:
      self.assertEquals(expected_value, getattr(entry, attr))
    else:
      self.assertEquals("caerSidi", entry.nickname)

