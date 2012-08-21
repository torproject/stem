"""
Unit tests for stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import Flag, RouterStatusEntry, _decode_fingerprint

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

class TestNetworkStatus(unittest.TestCase):
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
  
  def test_rse_minimal(self):
    """
    Parses a minimal router status entry.
    """
    
    entry = RouterStatusEntry(get_router_status_entry(), None)
    
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

