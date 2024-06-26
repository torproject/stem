"""
Unit tests for stem.directory.Fallback.
"""

import collections
import io
import re
import tempfile
import unittest

import stem
import stem.directory
import stem.util.conf

from unittest.mock import patch, Mock

# format as generated by https://gitlab.torproject.org/tpo/core/fallback-scripts/-/blob/main/src/main.rs
FALLBACK_GITLAB_CONTENT = b"""/* type=fallback */
/* version=4.0.0 */
/* timestamp=20210412000000 */
/* source=offer-list */
//
// Generated on: Fri, 04 Aug 2023 13:52:18 +0000

"185.220.101.209 orport=443 id=6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D"
" ipv6=[2a0b:f4c2:2:1::209]:443"
/* nickname=ForPrivacyNET */
/* extrainfo=0 */
/* ===== */
,
"213.32.104.213 orport=9000 id=A0296DDC9EC50AA42ED9D477D51DD4607D7876D3"
/* nickname=Unnamed */
/* extrainfo=0 */
/* ===== */
,
"""

HEADER = collections.OrderedDict((
  ('type', 'fallback'),
  ('version', '4.0.0'),
  ('timestamp', '20210412000000'),
  ('source', 'offer-list')
))


class TestFallback(unittest.TestCase):
  def test_equality(self):
    fallback_attr = {
      'address': '5.9.110.236',
      'or_port': 9001,
      'dir_port': 9030,
      'fingerprint': '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
      'nickname': 'rueckgrat',
      'has_extrainfo': True,
      'orport_v6': ('2a01:4f8:162:51e2::2', 9001),
      'header': collections.OrderedDict((
        ('type', 'fallback'),
        ('version', '2.0.0'),
        ('timestamp', '20170526090242'),
      )),
    }

    self.assertEqual(stem.directory.Fallback(**fallback_attr), stem.directory.Fallback(**fallback_attr))

    for attr in fallback_attr:
      for value in (None, 'something else'):
        second_fallback = stem.directory.Fallback(**fallback_attr)
        setattr(second_fallback, attr, value)
        self.assertNotEqual(stem.directory.Fallback(**fallback_attr), second_fallback)

  def test_from_cache(self):
    fallbacks = stem.directory.Fallback.from_cache()
    self.assertTrue(len(fallbacks) > 10)
    self.assertEqual('193.11.114.43', fallbacks['12AD30E5D25AA67F519780E2111E611A455FDC89'].address)

  @patch('urllib.request.urlopen', Mock(return_value = io.BytesIO(FALLBACK_GITLAB_CONTENT)))
  def test_from_remote(self):
    expected = {
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D': stem.directory.Fallback(
        address = '185.220.101.209',
        or_port = 443,
        fingerprint = '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D',
        nickname = 'ForPrivacyNET',
        has_extrainfo = False,
        orport_v6 = ('2a0b:f4c2:2:1::209', 443),
        header = HEADER,
      ),
      'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3': stem.directory.Fallback(
        address = '213.32.104.213',
        or_port = 9000,
        fingerprint = 'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3',
        nickname = 'Unnamed',
        has_extrainfo = False,
        orport_v6 = None,
        header = HEADER,
      ),
    }

    self.assertEqual(expected, stem.directory.Fallback.from_remote())

  @patch('urllib.request.urlopen', Mock(return_value = io.BytesIO(b'')))
  def test_from_remote_empty(self):
    self.assertRaisesRegex(stem.DownloadFailed, 'no content', stem.directory.Fallback.from_remote)

  @patch('urllib.request.urlopen', Mock(return_value = io.BytesIO(b'\n'.join(FALLBACK_GITLAB_CONTENT.splitlines()[1:]))))
  def test_from_remote_no_header(self):
    self.assertRaisesRegex(OSError, 'does not have a type field indicating it is fallback directory metadata', stem.directory.Fallback.from_remote)

  @patch('urllib.request.urlopen', Mock(return_value = io.BytesIO(FALLBACK_GITLAB_CONTENT.replace(b'version=4.0.0', b'version'))))
  def test_from_remote_malformed_header(self):
    self.assertRaisesRegex(OSError, 'Malformed fallback directory header line: /\\* version \\*/', stem.directory.Fallback.from_remote)

  def test_from_remote_malformed(self):
    test_values = {
      FALLBACK_GITLAB_CONTENT.replace(b'id=6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D', b''): 'Failed to parse mandatory data from:',
      FALLBACK_GITLAB_CONTENT.replace(b'185.220.101.209', b'185.220.101'): '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D (ForPrivacyNET) has an invalid IPv4 address: 185.220.101',
      FALLBACK_GITLAB_CONTENT.replace(b'orport=443', b'orport=7814713228'): '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D (ForPrivacyNET) has an invalid ORPort: 7814713228',
      FALLBACK_GITLAB_CONTENT.replace(b'ipv6=[2a0b', b'ipv6=[:::'): '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D (ForPrivacyNET) has an invalid IPv6 address: ::::f4c2:2:1::209',
      FALLBACK_GITLAB_CONTENT.replace(b'nickname=ForPrivacyNET', b'nickname=invalid~nickname'): '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D has an invalid nickname: invalid~nickname',
    }

    for entry, expected in test_values.items():
      with patch('urllib.request.urlopen', Mock(return_value = io.BytesIO(entry))):
        self.assertRaisesRegex(OSError, re.escape(expected), stem.directory.Fallback.from_remote)

  def test_persistence(self):
    expected = {
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D': stem.directory.Fallback(
        address = '185.220.101.209',
        or_port = 443,
        dir_port = None,
        fingerprint = '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D',
        nickname = 'ForPrivacyNET',
        has_extrainfo = False,
        orport_v6 = ('2a0b:f4c2:2:1::209', 443),
        header = HEADER,
      ),
      'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3': stem.directory.Fallback(
        address = '213.32.104.213',
        or_port = 9000,
        dir_port = None,
        fingerprint = 'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3',
        nickname = 'Unnamed',
        has_extrainfo = False,
        orport_v6 = None,
        header = HEADER,
      ),
    }

    excepted_config = {
      'tor_commit': ['abc'],
      'stem_commit': ['def'],
      'header.type': ['fallback'],
      'header.version': ['4.0.0'],
      'header.timestamp': ['20210412000000'],
      'header.source': ['offer-list'],
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D.address': ['185.220.101.209'],
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D.or_port': ['443'],
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D.nickname': ['ForPrivacyNET'],
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D.has_extrainfo': ['false'],
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D.orport6_address': ['2a0b:f4c2:2:1::209'],
      '6D6EC2A2E2ED8BFF2D4834F8D669D82FC2A9FA8D.orport6_port': ['443'],
      'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3.address': ['213.32.104.213'],
      'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3.or_port': ['9000'],
      'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3.nickname': ['Unnamed'],
      'A0296DDC9EC50AA42ED9D477D51DD4607D7876D3.has_extrainfo': ['false'],
    }

    with tempfile.NamedTemporaryFile(prefix = 'fallbacks.') as tmp:
      stem.directory.Fallback._write(expected, 'abc', 'def', HEADER, tmp.name)

      conf = stem.util.conf.Config()
      conf.load(tmp.name)
      self.assertEqual(excepted_config, dict(conf))

      self.assertEqual(expected, stem.directory.Fallback.from_cache(tmp.name))
