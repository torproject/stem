"""
Unit tests for the NetworkStatusDocument of stem.descriptor.networkstatus.
"""

import datetime
import unittest

import stem.version
from stem.descriptor import Flag
from stem.descriptor.networkstatus import HEADER_STATUS_DOCUMENT_FIELDS, FOOTER_STATUS_DOCUMENT_FIELDS, NetworkStatusDocument, DirectorySignature

NETWORK_STATUS_DOCUMENT_ATTR = {
  "network-status-version": "3",
  "vote-status": "consensus",
  "consensus-methods": "1 9",
  "consensus-method": "9",
  "published": "2012-09-02 22:00:00",
  "valid-after": "2012-09-02 22:00:00",
  "fresh-until": "2012-09-02 22:00:00",
  "valid-until": "2012-09-02 22:00:00",
  "voting-delay": "300 300",
  "known-flags": "Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid",
  "directory-footer": "",
  "directory-signature": "\n".join((
    "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 BF112F1C6D5543CFD0A32215ACABD4197B5279AD",
    "-----BEGIN SIGNATURE-----",
    "e1XH33ITaUYzXu+dK04F2dZwR4PhcOQgIuK859KGpU77/6lRuggiX/INk/4FJanJ",
    "ysCTE1K4xk4fH3N1Tzcv/x/gS4LUlIZz3yKfBnj+Xh3w12Enn9V1Gm1Vrhl+/YWH",
    "eweONYRZTTvgsB+aYsCoBuoBBpbr4Swlu64+85F44o4=",
    "-----END SIGNATURE-----")),
}

def get_network_status_document(attr = None, exclude = None, routers = None):
  """
  Constructs a minimal network status document with the given attributes. This
  places attributes in the proper order to be valid.
  
  :param dict attr: keyword/value mappings to be included in the entry
  :param list exclude: mandatory keywords to exclude from the entry
  :param list routers: lines with router status entry content
  
  :returns: str with customized router status entry content
  """
  
  descriptor_lines = []
  if attr is None: attr = {}
  if exclude is None: exclude = []
  if routers is None: routers = []
  attr = dict(attr) # shallow copy since we're destructive
  
  is_vote = attr.get("vote-status") == "vote"
  is_consensus = not is_vote
  
  header_content, footer_content = [], []
  
  for content, entries in ((header_content, HEADER_STATUS_DOCUMENT_FIELDS),
                           (footer_content, FOOTER_STATUS_DOCUMENT_FIELDS)):
    for field, in_votes, in_consensus, is_mandatory in entries:
      if field in exclude: continue
      
      if not field in attr:
        # Skip if it's not mandatory for this type of document. An exception is
        # made for the consensus' consensus-method and consensus-methods fields
        # since it influences validation, and is only missing for
        # consensus-method lower than 2.
        
        if field == "consensus-method" and is_consensus:
          pass
        elif field == "consensus-methods" and is_vote:
          pass
        elif not is_mandatory or not ((is_consensus and in_consensus) or (is_vote and in_votes)):
          continue
      
      if field in attr:
        value = attr[field]
        del attr[field]
      elif field in NETWORK_STATUS_DOCUMENT_ATTR:
        value = NETWORK_STATUS_DOCUMENT_ATTR[field]
      
      if value: value = " %s" % value
      content.append(field + value)
  
  remainder = []
  for attr_keyword, attr_value in attr.items():
    if attr_value: attr_value = " %s" % attr_value
    remainder.append(attr_keyword + attr_value)
  
  return "\n".join(header_content + remainder + routers + footer_content)

class TestNetworkStatusDocument(unittest.TestCase):
  def test_minimal_consensus(self):
    """
    Parses a minimal network status document.
    """
    
    document = NetworkStatusDocument(get_network_status_document())
    
    expected_known_flags = [Flag.AUTHORITY, Flag.BADEXIT, Flag.EXIT,
      Flag.FAST, Flag.GUARD, Flag.HSDIR, Flag.NAMED, Flag.RUNNING,
      Flag.STABLE, Flag.UNNAMED, Flag.V2DIR, Flag.VALID]
    
    sig = DirectorySignature("directory-signature " + NETWORK_STATUS_DOCUMENT_ATTR["directory-signature"])
    
    self.assertEqual((), document.routers)
    self.assertEqual("3", document.version)
    self.assertEqual(True, document.is_consensus)
    self.assertEqual(False, document.is_vote)
    self.assertEqual(9, document.consensus_method)
    self.assertEqual([], document.consensus_methods)
    self.assertEqual(None, document.published)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_after)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.fresh_until)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_until)
    self.assertEqual(300, document.vote_delay)
    self.assertEqual(300, document.dist_delay)
    self.assertEqual([], document.client_versions)
    self.assertEqual([], document.server_versions)
    self.assertEqual(expected_known_flags, document.known_flags)
    self.assertEqual({}, document.params)
    self.assertEqual([], document.directory_authorities)
    self.assertEqual(None, document.bandwidth_weights)
    self.assertEqual([sig], document.directory_signatures)
    self.assertEqual([], document.get_unrecognized_lines())
  
  def test_minimal_vote(self):
    """
    Parses a minimal network status document.
    """
    
    document = NetworkStatusDocument(get_network_status_document({"vote-status": "vote"}))
    
    expected_known_flags = [Flag.AUTHORITY, Flag.BADEXIT, Flag.EXIT,
      Flag.FAST, Flag.GUARD, Flag.HSDIR, Flag.NAMED, Flag.RUNNING,
      Flag.STABLE, Flag.UNNAMED, Flag.V2DIR, Flag.VALID]
    
    sig = DirectorySignature("directory-signature " + NETWORK_STATUS_DOCUMENT_ATTR["directory-signature"])
    
    self.assertEqual((), document.routers)
    self.assertEqual("3", document.version)
    self.assertEqual(False, document.is_consensus)
    self.assertEqual(True, document.is_vote)
    self.assertEqual(None, document.consensus_method)
    self.assertEqual([1, 9], document.consensus_methods)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.published)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_after)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.fresh_until)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_until)
    self.assertEqual(300, document.vote_delay)
    self.assertEqual(300, document.dist_delay)
    self.assertEqual([], document.client_versions)
    self.assertEqual([], document.server_versions)
    self.assertEqual(expected_known_flags, document.known_flags)
    self.assertEqual({}, document.params)
    self.assertEqual([], document.directory_authorities)
    self.assertEqual({}, document.bandwidth_weights)
    self.assertEqual([sig], document.directory_signatures)
    self.assertEqual([], document.get_unrecognized_lines())
  
  def test_missing_fields(self):
    """
    Excludes mandatory fields from both a vote and consensus document.
    """
    
    for is_consensus in (True, False):
      attr = {"vote-status": "consensus"} if is_consensus else {"vote-status": "vote"}
      is_vote = not is_consensus
      
      for entries in (HEADER_STATUS_DOCUMENT_FIELDS, FOOTER_STATUS_DOCUMENT_FIELDS):
        for field, in_votes, in_consensus, is_mandatory in entries:
          if is_mandatory and ((is_consensus and in_consensus) or (is_vote and in_votes)):
            content = get_network_status_document(attr, exclude = (field,))
            self.assertRaises(ValueError, NetworkStatusDocument, content)
            NetworkStatusDocument(content, False) # constructs without validation
  
  def test_misordered_fields(self):
    """
    Rearranges our descriptor fields.
    """
    
    self.skipTest("Needs a parser rewrite first")
    for is_consensus in (True, False):
      attr = {"vote-status": "consensus"} if is_consensus else {"vote-status": "vote"}
      lines = get_network_status_document(attr).split("\n")
      
      for i in xrange(len(lines) - 1):
        # swaps this line with the one after it
        test_lines = list(lines)
        test_lines[i], test_lines[i + 1] = test_lines[i + 1], test_lines[i]
        
        content = "\n".join(test_lines)
        self.assertRaises(ValueError, NetworkStatusDocument, content)
        NetworkStatusDocument(content, False) # constructs without validation
  
  def test_duplicate_fields(self):
    """
    Almost all fields can only appear once. Checking that duplicates cause
    validation errors.
    """
    
    for is_consensus in (True, False):
      attr = {"vote-status": "consensus"} if is_consensus else {"vote-status": "vote"}
      lines = get_network_status_document(attr).split("\n")
      
      for i in xrange(len(lines)):
        # Stop when we hit the 'directory-signature' for a couple reasons...
        # - that is the one field that can validly appear multiple times
        # - after it is a crypto blob, which won't trigger this kind of
        #   validation failure
        
        test_lines = list(lines)
        if test_lines[i].startswith("directory-signature "):
          break
        
        # duplicates the line
        test_lines.insert(i, test_lines[i])
        
        content = "\n".join(test_lines)
        self.assertRaises(ValueError, NetworkStatusDocument, content)
        NetworkStatusDocument(content, False) # constructs without validation
  
  def test_version(self):
    """
    Parses the network-status-version field, including trying to handle a
    different document version with the v3 parser.
    """
    
    content = get_network_status_document({"network-status-version": "3"})
    document = NetworkStatusDocument(content)
    self.assertEquals("3", document.version)
    
    content = get_network_status_document({"network-status-version": "4"})
    self.assertRaises(ValueError, NetworkStatusDocument, content)
    
    document = NetworkStatusDocument(content, False)
    self.assertEquals("4", document.version)
  
  def test_vote_status(self):
    """
    Parses the vote-status field.
    """
    
    content = get_network_status_document({"vote-status": "vote"})
    document = NetworkStatusDocument(content)
    self.assertEquals(False, document.is_consensus)
    self.assertEquals(True, document.is_vote)
    
    content = get_network_status_document({"vote-status": "consensus"})
    document = NetworkStatusDocument(content)
    self.assertEquals(True, document.is_consensus)
    self.assertEquals(False, document.is_vote)
    
    test_values = (
      "",
      "   ",
      "votee",
    )
    
    for test_value in test_values:
      content = get_network_status_document({"vote-status": test_value})
      self.assertRaises(ValueError, NetworkStatusDocument, content)
      
      document = NetworkStatusDocument(content, False)
      self.assertEquals(True, document.is_consensus)
      self.assertEquals(False, document.is_vote)
  
  def test_consensus_methods(self):
    """
    Parses the consensus-methods field.
    """
    
    content = get_network_status_document({"vote-status": "vote", "consensus-methods": "12 3 1 780"})
    document = NetworkStatusDocument(content)
    self.assertEquals([12, 3, 1, 780], document.consensus_methods)
    
    # check that we default to including consensus-method 1
    content = get_network_status_document({"vote-status": "vote"}, ("consensus-methods",))
    document = NetworkStatusDocument(content)
    self.assertEquals([1], document.consensus_methods)
    self.assertEquals(None, document.consensus_method)
    
    test_values = (
      ("", []),
      ("   ", []),
      ("1 2 3 a 5", [1, 2, 3, 5]),
      ("1 2 3 4.0 5", [1, 2, 3, 5]),
      ("2 3 4", [2, 3, 4]), # spec says version one must be included
    )
    
    for test_value, expected_consensus_methods in test_values:
      content = get_network_status_document({"vote-status": "vote", "consensus-methods": test_value})
      self.assertRaises(ValueError, NetworkStatusDocument, content)
      
      document = NetworkStatusDocument(content, False)
      self.assertEquals(expected_consensus_methods, document.consensus_methods)
  
  def test_consensus_method(self):
    """
    Parses the consensus-method field.
    """
    
    content = get_network_status_document({"consensus-method": "12"})
    document = NetworkStatusDocument(content)
    self.assertEquals(12, document.consensus_method)
    
    # check that we default to being consensus-method 1
    content = get_network_status_document(exclude = ("consensus-method",))
    document = NetworkStatusDocument(content)
    self.assertEquals(1, document.consensus_method)
    self.assertEquals([], document.consensus_methods)
    
    test_values = (
      "",
      "   ",
      "a",
      "1 2",
      "2.0",
    )
    
    for test_value in test_values:
      content = get_network_status_document({"consensus-method": test_value})
      self.assertRaises(ValueError, NetworkStatusDocument, content)
      
      document = NetworkStatusDocument(content, False)
      self.assertEquals(1, document.consensus_method)
  
  def test_time_fields(self):
    """
    Parses invalid published, valid-after, fresh-until, and valid-until fields.
    All are simply datetime values.
    """
    
    expected = datetime.datetime(2012, 9, 2, 22, 0, 0)
    test_value = "2012-09-02 22:00:00"
    
    content = get_network_status_document({
      "vote-status": "vote",
      "published": test_value,
      "valid-after": test_value,
      "fresh-until": test_value,
      "valid-until": test_value,
    })
    
    document = NetworkStatusDocument(content)
    self.assertEquals(expected, document.published)
    self.assertEquals(expected, document.valid_after)
    self.assertEquals(expected, document.fresh_until)
    self.assertEquals(expected, document.valid_until)
    
    test_values = (
      "",
      "   ",
      "2012-12-12",
      "2012-12-12 01:01:",
      "2012-12-12 01:a1:01",
    )
    
    for field in ('published', 'valid-after', 'fresh-until', 'valid-until'):
      attr = field.replace('-', '_')
      
      for test_value in test_values:
        content = get_network_status_document({"vote-status": "vote", field: test_value})
        self.assertRaises(ValueError, NetworkStatusDocument, content)
        
        document = NetworkStatusDocument(content, False)
        self.assertEquals(None, getattr(document, attr))
  
  def test_voting_delay(self):
    """
    Parses the voting-delay field.
    """
    
    content = get_network_status_document({"voting-delay": "12 345"})
    document = NetworkStatusDocument(content)
    self.assertEquals(12, document.vote_delay)
    self.assertEquals(345, document.dist_delay)
    
    test_values = (
      "",
      "   ",
      "1 a",
      "1\t2",
      "1 2.0",
    )
    
    for test_value in test_values:
      content = get_network_status_document({"voting-delay": test_value})
      self.assertRaises(ValueError, NetworkStatusDocument, content)
      
      document = NetworkStatusDocument(content, False)
      self.assertEquals(None, document.vote_delay)
      self.assertEquals(None, document.dist_delay)
  
  def test_version_lists(self):
    """
    Parses client-versions and server-versions fields. Both are comma separated
    lists of tor versions.
    """
    
    expected = [stem.version.Version("1.2.3.4"), stem.version.Version("56.789.12.34-alpha")]
    test_value = "1.2.3.4,56.789.12.34-alpha"
    
    content = get_network_status_document({"client-versions": test_value, "server-versions": test_value})
    document = NetworkStatusDocument(content)
    self.assertEquals(expected, document.client_versions)
    self.assertEquals(expected, document.server_versions)
    
    test_values = (
      ("", []),
      ("   ", []),
      ("1.2.3.4,", [stem.version.Version("1.2.3.4")]),
      ("1.2.3.4,1.2.3.a", [stem.version.Version("1.2.3.4")]),
    )
    
    for field in ('client-versions', 'server-versions'):
      attr = field.replace('-', '_')
      
      for test_value, expected_value in test_values:
        content = get_network_status_document({field: test_value})
        self.assertRaises(ValueError, NetworkStatusDocument, content)
        
        document = NetworkStatusDocument(content, False)
        self.assertEquals(expected_value, getattr(document, attr))
  
  def test_known_flags(self):
    """
    Parses some known-flag entries. Just exercising the field, there's not much
    to test here.
    """
    
    test_values = (
      ("", []),
      ("   ", []),
      ("BadExit", [Flag.BADEXIT]),
      ("BadExit ", [Flag.BADEXIT]),
      ("BadExit   ", [Flag.BADEXIT]),
      ("BadExit Fast", [Flag.BADEXIT, Flag.FAST]),
      ("BadExit Unrecognized Fast", [Flag.BADEXIT, "Unrecognized", Flag.FAST]),
    )
    
    for test_value, expected_value in test_values:
      content = get_network_status_document({"known-flags": test_value})
      document = NetworkStatusDocument(content)
      self.assertEquals(expected_value, document.known_flags)
  
  def test_params(self):
    """
    General testing for the 'params' line, exercising the happy cases.
    """
    
    content = get_network_status_document({"params": "CircuitPriorityHalflifeMsec=30000 bwauthpid=1 unrecognized=-122"})
    document = NetworkStatusDocument(content)
    self.assertEquals(30000, document.params["CircuitPriorityHalflifeMsec"])
    self.assertEquals(1, document.params["bwauthpid"])
    self.assertEquals(-122, document.params["unrecognized"])
    
    # empty params line
    content = get_network_status_document({"params": ""})
    document = NetworkStatusDocument(content)
    self.assertEquals({}, document.params)
  
  def test_params_malformed(self):
    """
    Parses a 'params' line with malformed content.
    """
    
    test_values = (
      "foo=",
      "foo=abc",
      "foo=+123",
      "foo=12\tbar=12",
    )
    
    for test_value in test_values:
      content = get_network_status_document({"params": test_value})
      self.assertRaises(ValueError, NetworkStatusDocument, content)
      
      document = NetworkStatusDocument(content, False)
      self.assertEquals({}, document.params)
  
  def test_params_range(self):
    """
    Check both the furthest valid 'params' values and values that are out of
    bounds.
    """
    
    test_values = (
      ("foo=2147483648", {"foo": 2147483648}, False),
      ("foo=-2147483649", {"foo": -2147483649}, False),
      ("foo=2147483647", {"foo": 2147483647}, True),
      ("foo=-2147483648", {"foo": -2147483648}, True),
    )
    
    for test_value, expected_value, is_ok in test_values:
      content = get_network_status_document({"params": test_value})
      
      if is_ok:
        document = NetworkStatusDocument(content)
      else:
        self.assertRaises(ValueError, NetworkStatusDocument, content)
        document = NetworkStatusDocument(content, False)
      
      self.assertEquals(expected_value, document.params)
  
  def test_params_misordered(self):
    """
    Check that the 'params' line is rejected if out of order.
    """
    
    content = get_network_status_document({"params": "unrecognized=-122 bwauthpid=1"})
    self.assertRaises(ValueError, NetworkStatusDocument, content)
    
    document = NetworkStatusDocument(content, False)
    self.assertEquals({"unrecognized": -122, "bwauthpid": 1}, document.params)

