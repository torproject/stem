"""
Unit tests for the stem.version.Version parsing and class.
"""

import unittest

import stem.util.system
import stem.version

from unittest.mock import Mock, patch

from stem.version import Version

VERSION_CMD_OUTPUT = """Mar 22 23:09:37.088 [notice] Tor v0.2.2.35 \
(git-73ff13ab3cc9570d). This is experimental software. Do not rely on it for \
strong anonymity. (Running on Linux i686)
%s"""

TOR_VERSION_OUTPUT = VERSION_CMD_OUTPUT % 'Tor version 0.2.2.35 (git-73ff13ab3cc9570d).'
MALFORMED_TOR_VERSION = VERSION_CMD_OUTPUT % 'Tor version 0.2.blah (git-73ff13ab3cc9570d).'
MISSING_TOR_VERSION = VERSION_CMD_OUTPUT % ''

TOR_VERSION_EXTRA_LINES = VERSION_CMD_OUTPUT % """
This is an extra line before the version
Tor version 0.2.2.35 (git-73ff13ab3cc9570d).
And an extra line afterward too
"""


class TestVersion(unittest.TestCase):
  @patch('stem.util.system.call')
  @patch.dict(stem.version.VERSION_CACHE)
  def test_get_system_tor_version(self, call_mock):
    call_mock.return_value = TOR_VERSION_OUTPUT.splitlines()

    version = stem.version.get_system_tor_version('tor_unit')

    self.assert_versions_match(version, 0, 2, 2, 35, None, 'git-73ff13ab3cc9570d')
    self.assertEqual('73ff13ab3cc9570d', version.git_commit)
    call_mock.assert_called_once_with('tor_unit --version')

    self.assertEqual(stem.version.VERSION_CACHE['tor_unit'], version)

  @patch('stem.util.system.call', Mock(return_value = TOR_VERSION_EXTRA_LINES.splitlines()))
  @patch.dict(stem.version.VERSION_CACHE)
  def test_get_system_tor_version_extra_lines(self):
    """
    Include extra text before and after the version.
    """

    version = stem.version.get_system_tor_version('tor_unit')
    self.assert_versions_match(version, 0, 2, 2, 35, None, 'git-73ff13ab3cc9570d')

  @patch('stem.util.system.call', Mock(return_value = MISSING_TOR_VERSION.splitlines()))
  @patch.dict(stem.version.VERSION_CACHE)
  def test_get_system_tor_version_missing(self):
    """
    Tor version output that doesn't include a version within it.
    """

    self.assertRaisesRegex(OSError, "'tor_unit --version' didn't provide a parseable version", stem.version.get_system_tor_version, 'tor_unit')

  @patch('stem.util.system.call', Mock(return_value = MALFORMED_TOR_VERSION.splitlines()))
  @patch.dict(stem.version.VERSION_CACHE)
  def test_get_system_tor_version_malformed(self):
    """
    Tor version output that has the correct basic formatting, but an invalid
    version.
    """

    self.assertRaisesWith(OSError, "'0.2.blah (git-73ff13ab3cc9570d)' isn't a properly formatted tor version", stem.version.get_system_tor_version, 'tor_unit')

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

  def test_with_multiple_extra(self):
    """
    Parse a version with multiple 'extra' fields.
    """

    version = Version('0.1.2 (release) (git-73ff13ab3cc9570d)')
    self.assert_versions_match(version, 0, 1, 2, None, None, 'release')
    self.assertEqual(['release', 'git-73ff13ab3cc9570d'], version.all_extra)
    self.assertEqual('73ff13ab3cc9570d', version.git_commit)

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
      self.assertEqual([], version.all_extra)
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
