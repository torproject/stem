"""
Unit tests for the DirectoryAuthority of stem.descriptor.networkstatus.
"""

import unittest

from stem.descriptor.networkstatus import DirectoryAuthority
from test.mocking import get_directory_authority, get_key_certificate, AUTHORITY_HEADER

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
  
  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """
    
    authority = get_directory_authority({"pepperjack": "is oh so tasty!"})
    self.assertEquals(["pepperjack is oh so tasty!"], authority.get_unrecognized_lines())
  
  def test_first_line(self):
    """
    Includes a non-mandatory field before the 'dir-source' line.
    """
    
    content = "ho-hum 567\n" + get_directory_authority(content = True)
    self.assertRaises(ValueError, DirectoryAuthority, content)
    
    authority = DirectoryAuthority(content, False)
    self.assertEqual("turtles", authority.nickname)
    self.assertEqual(["ho-hum 567"], authority.get_unrecognized_lines())
  
  def test_missing_fields(self):
    """
    Parse an authority where a mandatory field is missing.
    """
    
    for excluded_field in ("dir-source", "contact"):
      content = get_directory_authority(exclude = (excluded_field,), content = True)
      self.assertRaises(ValueError, DirectoryAuthority, content)
      
      authority = DirectoryAuthority(content, False)
      
      if excluded_field == "dir-source":
        self.assertEqual("Mike Perry <email>", authority.contact)
      else:
        self.assertEqual("turtles", authority.nickname)
  
  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """
    
    authority = get_directory_authority({"dir-source": AUTHORITY_HEADER[0][1] + "\n\n\n"})
    self.assertEqual("Mike Perry <email>", authority.contact)
  
  def test_duplicate_lines(self):
    """
    Duplicates linesin the entry.
    """
    
    lines = get_directory_authority(content = True).split("\n")
    
    for i in xrange(len(lines)):
      content = "\n".join(lines[:i] + [lines[i]] + lines[i:])
      self.assertRaises(ValueError, DirectoryAuthority, content)
      
      authority = DirectoryAuthority(content, False)
      self.assertEqual("turtles", authority.nickname)

