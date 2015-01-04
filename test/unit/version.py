"""
Unit tests for the stem.version.Version parsing and class.
"""

import unittest

import stem.util.system
import stem.version

from stem.version import Version

try:
  # added in python 3.3
  from unittest.mock import patch
except ImportError:
  from mock import patch

TOR_VERSION_OUTPUT = """Mar 22 23:09:37.088 [notice] Tor v0.2.2.35 \
(git-73ff13ab3cc9570d). This is experimental software. Do not rely on it for \
strong anonymity. (Running on Linux i686)
Tor version 0.2.2.35 (git-73ff13ab3cc9570d)."""


class TestVersion(unittest.TestCase):
  @patch('stem.util.system.call')
  @patch.dict(stem.version.VERSION_CACHE)
  def test_get_system_tor_version(self, call_mock):
    call_mock.return_value = TOR_VERSION_OUTPUT.splitlines()

    version = stem.version.get_system_tor_version()

    self.assert_versions_match(version, 0, 2, 2, 35, None, 'git-73ff13ab3cc9570d')
    self.assertEqual('73ff13ab3cc9570d', version.git_commit)
    call_mock.assert_called_once_with('tor --version')

    self.assertEqual({'tor': version}, stem.version.VERSION_CACHE)

  def test_parsing(self):
    """
    Tests parsing by the Version class constructor.
    """

    # valid versions with various number of compontents to the version

    version = Version('0.1.2.3-tag')
    self.assert_versions_match(version, 0, 1, 2, 3, 'tag', None)

    version = Version('0.1.2.3')
    self.assert_versions_match(version, 0, 1, 2, 3, None, None)

    version = Version('0.1.2-tag')
    self.assert_versions_match(version, 0, 1, 2, None, 'tag', None)

    version = Version('0.1.2')
    self.assert_versions_match(version, 0, 1, 2, None, None, None)

    # checks an empty tag
    version = Version('0.1.2.3-')
    self.assert_versions_match(version, 0, 1, 2, 3, '', None)

    version = Version('0.1.2-')
    self.assert_versions_match(version, 0, 1, 2, None, '', None)

    # check with extra informaton
    version = Version('0.1.2.3-tag (git-73ff13ab3cc9570d)')
    self.assert_versions_match(version, 0, 1, 2, 3, 'tag', 'git-73ff13ab3cc9570d')
    self.assertEqual('73ff13ab3cc9570d', version.git_commit)

    version = Version('0.1.2.3-tag ()')
    self.assert_versions_match(version, 0, 1, 2, 3, 'tag', '')

    version = Version('0.1.2 (git-73ff13ab3cc9570d)')
    self.assert_versions_match(version, 0, 1, 2, None, None, 'git-73ff13ab3cc9570d')

    # checks invalid version strings
    self.assertRaises(ValueError, stem.version.Version, '')
    self.assertRaises(ValueError, stem.version.Version, '1.2.3.4nodash')
    self.assertRaises(ValueError, stem.version.Version, '1.2.3.a')
    self.assertRaises(ValueError, stem.version.Version, '1.2.a.4')
    self.assertRaises(ValueError, stem.version.Version, '1x2x3x4')
    self.assertRaises(ValueError, stem.version.Version, '12.3')
    self.assertRaises(ValueError, stem.version.Version, '1.-2.3')

  def test_comparison(self):
    """
    Tests comparision between Version instances.
    """

    # check for basic incrementing in each portion
    self.assert_version_is_greater('1.1.2.3-tag', '0.1.2.3-tag')
    self.assert_version_is_greater('0.2.2.3-tag', '0.1.2.3-tag')
    self.assert_version_is_greater('0.1.3.3-tag', '0.1.2.3-tag')
    self.assert_version_is_greater('0.1.2.4-tag', '0.1.2.3-tag')
    self.assert_version_is_greater('0.1.2.3-ugg', '0.1.2.3-tag')
    self.assert_version_is_equal('0.1.2.3-tag', '0.1.2.3-tag')

    # check with common tags
    self.assert_version_is_greater('0.1.2.3-beta', '0.1.2.3-alpha')
    self.assert_version_is_greater('0.1.2.3-rc', '0.1.2.3-beta')

    # checks that a missing patch level equals zero
    self.assert_version_is_equal('0.1.2', '0.1.2.0')
    self.assert_version_is_equal('0.1.2-tag', '0.1.2.0-tag')

    # checks for missing patch or status
    self.assert_version_is_greater('0.1.2.3-tag', '0.1.2.3')
    self.assert_version_is_greater('0.1.2.3-tag', '0.1.2-tag')
    self.assert_version_is_greater('0.1.2.3-tag', '0.1.2')

    self.assert_version_is_equal('0.1.2.3', '0.1.2.3')
    self.assert_version_is_equal('0.1.2', '0.1.2')

  def test_nonversion_comparison(self):
    """
    Checks that we can be compared with other types.

    In python 3 on only equality comparisons work, greater than and less than
    comparisons result in a TypeError.
    """

    test_version = Version('0.1.2.3')
    self.assertNotEqual(test_version, None)
    self.assertNotEqual(test_version, 5)

  def test_string(self):
    """
    Tests the Version -> string conversion.
    """

    # checks conversion with various numbers of arguments
    self.assert_string_matches('0.1.2.3-tag')
    self.assert_string_matches('0.1.2.3')
    self.assert_string_matches('0.1.2')

  def test_requirements_greater_than(self):
    """
    Checks a VersionRequirements with a single greater_than rule.
    """

    requirements = stem.version._VersionRequirements()
    requirements.greater_than(Version('0.2.2.36'))

    self.assertTrue(Version('0.2.2.36') >= requirements)
    self.assertTrue(Version('0.2.2.37') >= requirements)
    self.assertTrue(Version('0.2.3.36') >= requirements)
    self.assertFalse(Version('0.2.2.35') >= requirements)
    self.assertFalse(Version('0.2.1.38') >= requirements)

    requirements = stem.version._VersionRequirements()
    requirements.greater_than(Version('0.2.2.36'), False)

    self.assertFalse(Version('0.2.2.35') >= requirements)
    self.assertFalse(Version('0.2.2.36') >= requirements)
    self.assertTrue(Version('0.2.2.37') >= requirements)

  def test_requirements_less_than(self):
    """
    Checks a VersionRequirements with a single less_than rule.
    """

    requirements = stem.version._VersionRequirements()
    requirements.less_than(Version('0.2.2.36'))

    self.assertTrue(Version('0.2.2.36') >= requirements)
    self.assertTrue(Version('0.2.2.35') >= requirements)
    self.assertTrue(Version('0.2.1.38') >= requirements)
    self.assertFalse(Version('0.2.2.37') >= requirements)
    self.assertFalse(Version('0.2.3.36') >= requirements)

    requirements = stem.version._VersionRequirements()
    requirements.less_than(Version('0.2.2.36'), False)

    self.assertFalse(Version('0.2.2.37') >= requirements)
    self.assertFalse(Version('0.2.2.36') >= requirements)
    self.assertTrue(Version('0.2.2.35') >= requirements)

  def test_requirements_in_range(self):
    """
    Checks a VersionRequirements with a single in_range rule.
    """

    requirements = stem.version._VersionRequirements()
    requirements.in_range(Version('0.2.2.36'), Version('0.2.2.38'))

    self.assertFalse(Version('0.2.2.35') >= requirements)
    self.assertTrue(Version('0.2.2.36') >= requirements)
    self.assertTrue(Version('0.2.2.37') >= requirements)
    self.assertFalse(Version('0.2.2.38') >= requirements)

    # rule for 'anything in the 0.2.2.x series'
    requirements = stem.version._VersionRequirements()
    requirements.in_range(Version('0.2.2.0'), Version('0.2.3.0'))

    for index in range(0, 100):
      self.assertTrue(Version('0.2.2.%i' % index) >= requirements)

  def test_requirements_multiple_rules(self):
    """
    Checks a VersionRequirements is the logical 'or' when it has multiple rules.
    """

    # rule to say 'anything but the 0.2.2.x series'
    requirements = stem.version._VersionRequirements()
    requirements.greater_than(Version('0.2.3.0'))
    requirements.less_than(Version('0.2.2.0'), False)

    self.assertTrue(Version('0.2.3.0') >= requirements)
    self.assertFalse(Version('0.2.2.0') >= requirements)

    for index in range(0, 100):
      self.assertFalse(Version('0.2.2.%i' % index) >= requirements)

  def assert_versions_match(self, version, major, minor, micro, patch, status, extra):
    """
    Asserts that the values for a types.Version instance match the given
    values.
    """

    self.assertEqual(major, version.major)
    self.assertEqual(minor, version.minor)
    self.assertEqual(micro, version.micro)
    self.assertEqual(patch, version.patch)
    self.assertEqual(status, version.status)
    self.assertEqual(extra, version.extra)

    if extra is None:
      self.assertEqual(None, version.git_commit)

  def assert_version_is_greater(self, first_version, second_version):
    """
    Asserts that the parsed version of the first version is greate than the
    second (also checking the inverse).
    """

    version1 = Version(first_version)
    version2 = Version(second_version)
    self.assertEqual(version1 > version2, True)
    self.assertEqual(version1 < version2, False)

  def assert_version_is_equal(self, first_version, second_version):
    """
    Asserts that the parsed version of the first version equals the second.
    """

    version1 = Version(first_version)
    version2 = Version(second_version)
    self.assertEqual(version1, version2)

  def assert_string_matches(self, version):
    """
    Parses the given version string then checks that its string representation
    matches the input.
    """

    self.assertEqual(version, str(Version(version)))
