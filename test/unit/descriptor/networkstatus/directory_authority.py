"""
Unit tests for the DirectoryAuthority of stem.descriptor.networkstatus.
"""

import unittest

import test.require

from stem.descriptor.networkstatus import (
  DirectoryAuthority,
  KeyCertificate,
)

DIR_SOURCE_LINE = 'turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090'


class TestDirectoryAuthority(unittest.TestCase):
  def test_minimal_consensus_authority(self):
    """
    Parses a minimal directory authority for a consensus.
    """

    authority = DirectoryAuthority.create()

    self.assertTrue(authority.nickname.startswith('Unnamed'))
    self.assertEqual(40, len(authority.fingerprint))
    self.assertEqual('no.place.com', authority.hostname)
    self.assertEqual(9030, authority.dir_port)
    self.assertEqual(9090, authority.or_port)
    self.assertEqual(False, authority.is_legacy)
    self.assertEqual('Mike Perry <email>', authority.contact)
    self.assertEqual(40, len(authority.vote_digest))
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual(None, authority.key_certificate)
    self.assertEqual([], authority.get_unrecognized_lines())

  def test_minimal_vote_authority(self):
    """
    Parses a minimal directory authority for a vote.
    """

    authority = DirectoryAuthority.create(is_vote = True)

    self.assertTrue(authority.nickname.startswith('Unnamed'))
    self.assertEqual(40, len(authority.fingerprint))
    self.assertEqual('no.place.com', authority.hostname)
    self.assertEqual(9030, authority.dir_port)
    self.assertEqual(9090, authority.or_port)
    self.assertEqual(False, authority.is_legacy)
    self.assertEqual('Mike Perry <email>', authority.contact)
    self.assertEqual(None, authority.vote_digest)
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual([], authority.get_unrecognized_lines())

  @test.require.cryptography
  def test_descriptor_signing(self):
    self.assertRaisesWith(NotImplementedError, 'Signing of DirectoryAuthority not implemented', DirectoryAuthority.create, sign = True)

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    authority = DirectoryAuthority.create({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], authority.get_unrecognized_lines())

  def test_legacy_authority(self):
    """
    Parses an authority using the '-legacy' format.
    """

    content = 'dir-source gabelmoo-legacy 81349FC1F2DBA2C2C11B45CB9706637D480AB913 131.188.40.189 131.188.40.189 80 443'
    authority = DirectoryAuthority(content, is_vote = False)

    self.assertEqual('gabelmoo-legacy', authority.nickname)
    self.assertEqual('81349FC1F2DBA2C2C11B45CB9706637D480AB913', authority.fingerprint)
    self.assertEqual('131.188.40.189', authority.hostname)
    self.assertEqual('131.188.40.189', authority.address)
    self.assertEqual(80, authority.dir_port)
    self.assertEqual(443, authority.or_port)
    self.assertEqual(True, authority.is_legacy)
    self.assertEqual(None, authority.contact)
    self.assertEqual(None, authority.vote_digest)
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual(None, authority.key_certificate)
    self.assertEqual([], authority.get_unrecognized_lines())

  def test_first_line(self):
    """
    Includes a non-mandatory field before the 'dir-source' line.
    """

    content = b'ho-hum 567\n' + DirectoryAuthority.content()
    self.assertRaises(ValueError, DirectoryAuthority, content, True)

    authority = DirectoryAuthority(content, False)
    self.assertTrue(authority.nickname.startswith('Unnamed'))
    self.assertEqual(['ho-hum 567'], authority.get_unrecognized_lines())

  def test_missing_fields(self):
    """
    Parse an authority where a mandatory field is missing.
    """

    for excluded_field in ('dir-source', 'contact'):
      content = DirectoryAuthority.content(exclude = (excluded_field,))
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)

      if excluded_field == 'dir-source':
        self.assertEqual('Mike Perry <email>', authority.contact)
      else:
        self.assertTrue(authority.nickname.startswith('Unnamed'))

  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """

    authority = DirectoryAuthority.create({'dir-source': DIR_SOURCE_LINE + '\n\n\n'})
    self.assertEqual('Mike Perry <email>', authority.contact)

  def test_duplicate_lines(self):
    """
    Duplicates linesin the entry.
    """

    lines = DirectoryAuthority.content().split(b'\n')

    for index, duplicate_line in enumerate(lines):
      content = b'\n'.join(lines[:index] + [duplicate_line] + lines[index:])
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)
      self.assertTrue(authority.nickname.startswith('Unnamed'))

  def test_missing_dir_source_field(self):
    """
    Excludes fields from the 'dir-source' line.
    """

    for missing_value in DIR_SOURCE_LINE.split(' '):
      dir_source = DIR_SOURCE_LINE.replace(missing_value, '').replace('  ', ' ')
      content = DirectoryAuthority.content({'dir-source': dir_source})
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)

      self.assertEqual(None, authority.nickname)
      self.assertEqual(None, authority.fingerprint)
      self.assertEqual(None, authority.hostname)
      self.assertEqual(None, authority.address)
      self.assertEqual(None, authority.dir_port)
      self.assertEqual(None, authority.or_port)

  def test_malformed_fingerprint(self):
    """
    Includes a malformed fingerprint on the 'dir-source' line.
    """

    test_values = (
      '',
      'zzzzz',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    )

    for value in test_values:
      dir_source = DIR_SOURCE_LINE.replace('27B6B5996C426270A5C95488AA5BCEB6BCC86956', value)
      content = DirectoryAuthority.content({'dir-source': dir_source})
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)
      self.assertEqual(None, authority.fingerprint)

  def test_malformed_address(self):
    """
    Includes a malformed ip address on the 'dir-source' line.
    """

    test_values = (
      '',
      '71.35.150.',
      '71.35..29',
      '71.35.150',
      '71.35.150.256',
      '[fd9f:2e19:3bcf::02:9970]',
    )

    for value in test_values:
      dir_source = DIR_SOURCE_LINE.replace('76.73.17.194', value)
      content = DirectoryAuthority.content({'dir-source': dir_source})
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)
      self.assertEqual(None, authority.address)

  def test_malformed_port(self):
    """
    Includes a malformed orport or dirport on the 'dir-source' line.
    """

    test_values = (
      '',
      '-1',
      '399482',
      'blarg',
    )

    for value in test_values:
      for include_or_port in (False, True):
        for include_dir_port in (False, True):
          if not include_or_port and not include_dir_port:
            continue

          dir_source = DIR_SOURCE_LINE

          if include_or_port:
            dir_source = dir_source.replace('9090', value)

          if include_dir_port:
            dir_source = dir_source.replace('9030', value)

          content = DirectoryAuthority.content({'dir-source': dir_source})
          self.assertRaises(ValueError, DirectoryAuthority, content, True)

          authority = DirectoryAuthority(content, False)

          actual_value = authority.or_port if include_or_port else authority.dir_port
          self.assertEqual(None, actual_value)

  def test_legacy_dir_key(self):
    """
    Includes a 'legacy-dir-key' line with both valid and invalid content.
    """

    test_value = '65968CCB6BECB5AA88459C5A072624C6995B6B72'
    authority = DirectoryAuthority.create({'legacy-dir-key': test_value}, is_vote = True)
    self.assertEqual(test_value, authority.legacy_dir_key)

    # check that we'll fail if legacy-dir-key appears in a consensus
    content = DirectoryAuthority.content({'legacy-dir-key': test_value})
    self.assertRaises(ValueError, DirectoryAuthority, content, True)

    test_values = (
      '',
      'zzzzz',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    )

    for value in test_values:
      content = DirectoryAuthority.content({'legacy-dir-key': value})
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)
      self.assertEqual(None, authority.legacy_dir_key)

  def test_key_certificate(self):
    """
    Includes or exclude a key certificate from the directory entry.
    """

    key_cert = KeyCertificate.content()

    # include a key cert with a consensus
    content = DirectoryAuthority.content() + b'\n' + key_cert
    self.assertRaises(ValueError, DirectoryAuthority, content, True)

    authority = DirectoryAuthority(content, False)
    self.assertTrue(authority.nickname.startswith('Unnamed'))

    # exclude  key cert from a vote

    content = b'\n'.join(DirectoryAuthority.content(is_vote = True).splitlines()[:-5])
    self.assertRaises(ValueError, DirectoryAuthority, content, True, True)

    authority = DirectoryAuthority(content, False, True)
    self.assertTrue(authority.nickname.startswith('Unnamed'))
