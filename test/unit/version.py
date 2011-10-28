"""
Unit tests for the types.Version parsing and class.
"""

import unittest
import stem.types

class TestVerionFunctions(unittest.TestCase):
  """
  Tests methods and functions related to 'types.Version'.
  """
  
  def test_parsing(self):
    """
    Tests parsing by the Version class constructor.
    """
    
    # valid versions with various number of compontents to the version
    version = stem.types.Version("0.1.2.3-tag")
    self.assert_versions_match(version, 0, 1, 2, 3, "tag")
    
    version = stem.types.Version("0.1.2.3")
    self.assert_versions_match(version, 0, 1, 2, 3, None)
    
    version = stem.types.Version("0.1.2-tag")
    self.assert_versions_match(version, 0, 1, 2, None, "tag")
    
    version = stem.types.Version("0.1.2")
    self.assert_versions_match(version, 0, 1, 2, None, None)
    
    # checks an empty tag
    version = stem.types.Version("0.1.2.3-")
    self.assert_versions_match(version, 0, 1, 2, 3, "")
    
    version = stem.types.Version("0.1.2-")
    self.assert_versions_match(version, 0, 1, 2, None, "")
    
    # checks invalid version strings
    self.assertRaises(ValueError, stem.types.Version, "")
    self.assertRaises(ValueError, stem.types.Version, "1.2.3.4nodash")
    self.assertRaises(ValueError, stem.types.Version, "1.2.3.a")
    self.assertRaises(ValueError, stem.types.Version, "1.2.a.4")
    self.assertRaises(ValueError, stem.types.Version, "12.3")
    self.assertRaises(ValueError, stem.types.Version, "1.-2.3")
  
  def test_comparison(self):
    """
    Tests comparision between Version instances.
    """
    
    # check for basic incrementing in each portion
    self.assert_version_is_greater("1.1.2.3-tag", "0.1.2.3-tag")
    self.assert_version_is_greater("0.2.2.3-tag", "0.1.2.3-tag")
    self.assert_version_is_greater("0.1.3.3-tag", "0.1.2.3-tag")
    self.assert_version_is_greater("0.1.2.4-tag", "0.1.2.3-tag")
    self.assert_version_is_greater("0.1.2.3-ugg", "0.1.2.3-tag")
    self.assert_version_is_equal("0.1.2.3-tag", "0.1.2.3-tag")
    
    # checks that a missing patch level equals zero
    self.assert_version_is_equal("0.1.2", "0.1.2.0")
    self.assert_version_is_equal("0.1.2-tag", "0.1.2.0-tag")
    
    # checks for missing patch or status
    self.assert_version_is_greater("0.1.2.3-tag", "0.1.2.3")
    self.assert_version_is_greater("0.1.2.3-tag", "0.1.2-tag")
    self.assert_version_is_greater("0.1.2.3-tag", "0.1.2")
    
    self.assert_version_is_equal("0.1.2.3", "0.1.2.3")
    self.assert_version_is_equal("0.1.2", "0.1.2")
  
  def test_string(self):
    """
    Tests the Version -> string conversion.
    """
    
    # checks conversion with various numbers of arguments
    
    self.assert_string_matches("0.1.2.3-tag")
    self.assert_string_matches("0.1.2.3")
    self.assert_string_matches("0.1.2")
  
  def assert_versions_match(self, version, major, minor, micro, patch, status):
    """
    Asserts that the values for a types.Version instance match the given
    values.
    """
    
    self.assertEqual(version.major, major)
    self.assertEqual(version.minor, minor)
    self.assertEqual(version.micro, micro)
    self.assertEqual(version.patch, patch)
    self.assertEqual(version.status, status)
  
  def assert_version_is_greater(self, first_version, second_version):
    """
    Asserts that the parsed version of the first version is greate than the
    second (also checking the inverse).
    """
    
    version1 = stem.types.Version(first_version)
    version2 = stem.types.Version(second_version)
    self.assertEqual(version1 > version2, True)
    self.assertEqual(version1 < version2, False)
  
  def assert_version_is_equal(self, first_version, second_version):
    """
    Asserts that the parsed version of the first version equals the second.
    """
    
    version1 = stem.types.Version(first_version)
    version2 = stem.types.Version(second_version)
    self.assertEqual(version1, version2)
  
  def assert_string_matches(self, version):
    """
    Parses the given version string then checks that its string representation
    matches the input.
    """
    
    self.assertEqual(version, str(stem.types.Version(version)))

