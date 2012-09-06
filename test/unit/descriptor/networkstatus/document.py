"""
Unit tests for the NetworkStatusDocument of stem.descriptor.networkstatus.
"""

import datetime
import unittest

from stem.descriptor.networkstatus import HEADER_STATUS_DOCUMENT_FIELDS, FOOTER_STATUS_DOCUMENT_FIELDS, Flag, NetworkStatusDocument, DirectorySignature

NETWORK_STATUS_DOCUMENT_ATTR = {
  "network-status-version": "3",
  "vote-status": "consensus",
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
        # made for the consensus' consensus-method field since it influences
        # validation, and is only missing for consensus-method lower than 2.
        
        if field == "consensus-method" and is_consensus:
          pass
        elif not is_mandatory or not ((is_consensus and in_consensus) or (is_vote and in_vote)):
          continue
      
      if field in attr:
        value = attr[keyword]
        del attr[keyword]
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
  def test_document_minimal(self):
    """
    Parses a minimal network status document.
    """
    
    document = NetworkStatusDocument(get_network_status_document())
    
    expected_known_flags = [Flag.AUTHORITY, Flag.BADEXIT, Flag.EXIT,
      Flag.FAST, Flag.GUARD, Flag.HSDIR, Flag.NAMED, Flag.RUNNING,
      Flag.STABLE, Flag.UNNAMED, Flag.V2DIR, Flag.VALID]
    
    sig = DirectorySignature("directory-signature " + NETWORK_STATUS_DOCUMENT_ATTR["directory-signature"])
    
    self.assertEqual((), document.routers)
    self.assertEqual("3", document.network_status_version)
    self.assertEqual("consensus", document.vote_status)
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
    self.assertEqual(None, document.params)
    self.assertEqual([], document.directory_authorities)
    self.assertEqual(None, document.bandwidth_weights)
    self.assertEqual([sig], document.directory_signatures)
    self.assertEqual([], document.get_unrecognized_lines())

