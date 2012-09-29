"""
Unit tests for the DirectoryAuthority of stem.descriptor.networkstatus.
"""

import unittest

from test.mocking import get_directory_authority, get_key_certificate

class TestDirectoryAuthority(unittest.TestCase):
  def test_minimal_consensus_authority(self):
    """
    Parses a minimal directory authority for a consensus.
    """
    
    authority = get_directory_authority()
    
    self.assertEqual("turtles", authority.nickname)
    self.assertEqual("27B6B5996C426270A5C95488AA5BCEB6BCC86956", authority.fingerprint)
    self.assertEqual("no.place.com", authority.hostname)
    self.assertEqual("76.73.17.194", authority.address)
    self.assertEqual(9030, authority.dir_port)
    self.assertEqual(9090, authority.or_port)
    self.assertEqual("Mike Perry <email>", authority.contact)
    self.assertEqual("0B6D1E9A300B895AA2D0B427F92917B6995C3C1C", authority.vote_digest)
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual(None, authority.key_certificate)
    self.assertEqual([], authority.get_unrecognized_lines())
  
  def test_minimal_vote_authority(self):
    """
    Parses a minimal directory authority for a vote.
    """
    
    authority = get_directory_authority(is_vote = True)
    
    self.assertEqual("turtles", authority.nickname)
    self.assertEqual("27B6B5996C426270A5C95488AA5BCEB6BCC86956", authority.fingerprint)
    self.assertEqual("no.place.com", authority.hostname)
    self.assertEqual("76.73.17.194", authority.address)
    self.assertEqual(9030, authority.dir_port)
    self.assertEqual(9090, authority.or_port)
    self.assertEqual("Mike Perry <email>", authority.contact)
    self.assertEqual(None, authority.vote_digest)
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual(get_key_certificate(), authority.key_certificate)
    self.assertEqual([], authority.get_unrecognized_lines())

