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

    self.assertEqual('turtles', authority.nickname)
    self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', authority.fingerprint)
    self.assertEqual('no.place.com', authority.hostname)
    self.assertEqual('76.73.17.194', authority.address)
    self.assertEqual(9030, authority.dir_port)
    self.assertEqual(9090, authority.or_port)
    self.assertEqual(False, authority.is_legacy)
    self.assertEqual('Mike Perry <email>', authority.contact)
    self.assertEqual('0B6D1E9A300B895AA2D0B427F92917B6995C3C1C', authority.vote_digest)
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual(None, authority.key_certificate)
    self.assertEqual([], authority.get_unrecognized_lines())

  def test_minimal_vote_authority(self):
    """
    Parses a minimal directory authority for a vote.
    """

    authority = get_directory_authority(is_vote = True)

    self.assertEqual('turtles', authority.nickname)
    self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', authority.fingerprint)
    self.assertEqual('no.place.com', authority.hostname)
    self.assertEqual('76.73.17.194', authority.address)
    self.assertEqual(9030, authority.dir_port)
    self.assertEqual(9090, authority.or_port)
    self.assertEqual(False, authority.is_legacy)
    self.assertEqual('Mike Perry <email>', authority.contact)
    self.assertEqual(None, authority.vote_digest)
    self.assertEqual(None, authority.legacy_dir_key)
    self.assertEqual(get_key_certificate(), authority.key_certificate)
    self.assertEqual([], authority.get_unrecognized_lines())

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    authority = get_directory_authority({'pepperjack': 'is oh so tasty!'})
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

    content = b'ho-hum 567\n' + get_directory_authority(content = True)
    self.assertRaises(ValueError, DirectoryAuthority, content, True)

    authority = DirectoryAuthority(content, False)
    self.assertEqual('turtles', authority.nickname)
    self.assertEqual(['ho-hum 567'], authority.get_unrecognized_lines())

  def test_missing_fields(self):
    """
    Parse an authority where a mandatory field is missing.
    """

    for excluded_field in ('dir-source', 'contact'):
      content = get_directory_authority(exclude = (excluded_field,), content = True)
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)

      if excluded_field == 'dir-source':
        self.assertEqual('Mike Perry <email>', authority.contact)
      else:
        self.assertEqual('turtles', authority.nickname)

  def test_blank_lines(self):
    """
    Includes blank lines, which should be ignored.
    """

    authority = get_directory_authority({'dir-source': AUTHORITY_HEADER[0][1] + '\n\n\n'})
    self.assertEqual('Mike Perry <email>', authority.contact)

  def test_duplicate_lines(self):
    """
    Duplicates linesin the entry.
    """

    lines = get_directory_authority(content = True).split(b'\n')

    for index, duplicate_line in enumerate(lines):
      content = b'\n'.join(lines[:index] + [duplicate_line] + lines[index:])
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)
      self.assertEqual('turtles', authority.nickname)

  def test_missing_dir_source_field(self):
    """
    Excludes fields from the 'dir-source' line.
    """

    for missing_value in AUTHORITY_HEADER[0][1].split(' '):
      dir_source = AUTHORITY_HEADER[0][1].replace(missing_value, '').replace('  ', ' ')
      content = get_directory_authority({'dir-source': dir_source}, content = True)
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
      dir_source = AUTHORITY_HEADER[0][1].replace('27B6B5996C426270A5C95488AA5BCEB6BCC86956', value)
      content = get_directory_authority({'dir-source': dir_source}, content = True)
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
      dir_source = AUTHORITY_HEADER[0][1].replace('76.73.17.194', value)
      content = get_directory_authority({'dir-source': dir_source}, content = True)
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

          dir_source = AUTHORITY_HEADER[0][1]

          if include_or_port:
            dir_source = dir_source.replace('9090', value)

          if include_dir_port:
            dir_source = dir_source.replace('9030', value)

          content = get_directory_authority({'dir-source': dir_source}, content = True)
          self.assertRaises(ValueError, DirectoryAuthority, content, True)

          authority = DirectoryAuthority(content, False)

          actual_value = authority.or_port if include_or_port else authority.dir_port
          self.assertEqual(None, actual_value)

  def test_legacy_dir_key(self):
    """
    Includes a 'legacy-dir-key' line with both valid and invalid content.
    """

    test_value = '65968CCB6BECB5AA88459C5A072624C6995B6B72'
    authority = get_directory_authority({'legacy-dir-key': test_value}, is_vote = True)
    self.assertEqual(test_value, authority.legacy_dir_key)

    # check that we'll fail if legacy-dir-key appears in a consensus
    content = get_directory_authority({'legacy-dir-key': test_value}, content = True)
    self.assertRaises(ValueError, DirectoryAuthority, content, True)

    test_values = (
      '',
      'zzzzz',
      'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz',
    )

    for value in test_values:
      content = get_directory_authority({'legacy-dir-key': value}, content = True)
      self.assertRaises(ValueError, DirectoryAuthority, content, True)

      authority = DirectoryAuthority(content, False)
      self.assertEqual(None, authority.legacy_dir_key)

  def test_key_certificate(self):
    """
    Includes or exclude a key certificate from the directory entry.
    """

    key_cert = get_key_certificate(content = True)

    # include a key cert with a consensus
    content = get_directory_authority(content = True) + b'\n' + key_cert
    self.assertRaises(ValueError, DirectoryAuthority, content, True)

    authority = DirectoryAuthority(content, False)
    self.assertEqual('turtles', authority.nickname)

    # exclude  key cert from a vote
    content = get_directory_authority(content = True, is_vote = True).replace(b'\n' + key_cert, b'')
    self.assertRaises(ValueError, DirectoryAuthority, content, True, True)

    authority = DirectoryAuthority(content, False, True)
    self.assertEqual('turtles', authority.nickname)
