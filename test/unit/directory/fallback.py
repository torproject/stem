"""
Unit tests for stem.directory.Fallback.
"""

import io
import re
import tempfile
import unittest

import stem
import stem.directory
import stem.util.conf

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

try:
  # added in python 3.3
  from unittest.mock import patch, Mock
except ImportError:
  from mock import patch, Mock

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'

FALLBACK_GITWEB_CONTENT = b"""\
/* type=fallback */
/* version=2.0.0 */
/* timestamp=20170526090242 */
/* ===== */
/* Whitelist & blacklist excluded 1326 of 1513 candidates. */
/* Checked IPv4 DirPorts served a consensus within 15.0s. */
/*
Final Count: 151 (Eligible 187, Target 392 (1963 * 0.20), Max 200)
Excluded: 36 (Same Operator 27, Failed/Skipped Download 9, Excess 0)
Bandwidth Range: 1.3 - 40.0 MByte/s
*/
/*
Onionoo Source: details Date: 2017-05-16 07:00:00 Version: 4.0
URL: https:onionoo.torproject.orgdetails?fields=fingerprint%2Cnickname%2Ccontact%2Clast_changed_address_or_port%2Cconsensus_weight%2Cadvertised_bandwidth%2Cor_addresses%2Cdir_address%2Crecommended_version%2Cflags%2Ceffective_family%2Cplatform&flag=V2Dir&type=relay&last_seen_days=-0&first_seen_days=30-
*/
/*
Onionoo Source: uptime Date: 2017-05-16 07:00:00 Version: 4.0
URL: https:onionoo.torproject.orguptime?first_seen_days=30-&flag=V2Dir&type=relay&last_seen_days=-0
*/
/* ===== */
"5.9.110.236:9030 orport=9001 id=0756B7CD4DFC8182BE23143FAC0642F515182CEB"
" ipv6=[2a01:4f8:162:51e2::2]:9001"
/* nickname=rueckgrat */
/* extrainfo=1 */
/* ===== */
,
"193.171.202.146:9030 orport=9001 id=01A9258A46E97FF8B2CAC7910577862C14F2C524"
/* nickname= */
/* extrainfo=0 */
/* ===== */
"""

HEADER = OrderedDict((
  ('type', 'fallback'),
  ('version', '2.0.0'),
  ('timestamp', '20170526090242'),
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
      'header': OrderedDict((
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
    self.assertEqual('185.13.39.197', fallbacks['001524DD403D729F08F7E5D77813EF12756CFA8D'].address)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(FALLBACK_GITWEB_CONTENT)))
  def test_from_remote(self):
    expected = {
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB': stem.directory.Fallback(
        address = '5.9.110.236',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
        nickname = 'rueckgrat',
        has_extrainfo = True,
        orport_v6 = ('2a01:4f8:162:51e2::2', 9001),
        header = HEADER,
      ),
      '01A9258A46E97FF8B2CAC7910577862C14F2C524': stem.directory.Fallback(
        address = '193.171.202.146',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '01A9258A46E97FF8B2CAC7910577862C14F2C524',
        nickname = None,
        has_extrainfo = False,
        orport_v6 = None,
        header = HEADER,
      ),
    }

    self.assertEqual(expected, stem.directory.Fallback.from_remote())

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'')))
  def test_from_remote_empty(self):
    self.assertRaisesRegexp(stem.DownloadFailed, 'no content', stem.directory.Fallback.from_remote)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'\n'.join(FALLBACK_GITWEB_CONTENT.splitlines()[1:]))))
  def test_from_remote_no_header(self):
    self.assertRaisesRegexp(IOError, 'does not have a type field indicating it is fallback directory metadata', stem.directory.Fallback.from_remote)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(FALLBACK_GITWEB_CONTENT.replace(b'version=2.0.0', b'version'))))
  def test_from_remote_malformed_header(self):
    self.assertRaisesRegexp(IOError, 'Malformed fallback directory header line: /\\* version \\*/', stem.directory.Fallback.from_remote)

  def test_from_remote_malformed(self):
    test_values = {
      FALLBACK_GITWEB_CONTENT.replace(b'id=0756B7CD4DFC8182BE23143FAC0642F515182CEB', b''): 'Failed to parse mandatory data from:',
      FALLBACK_GITWEB_CONTENT.replace(b'5.9.110.236', b'5.9.110'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB (rueckgrat) has an invalid IPv4 address: 5.9.110',
      FALLBACK_GITWEB_CONTENT.replace(b':9030', b':7814713228'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB (rueckgrat) has an invalid DirPort: 7814713228',
      FALLBACK_GITWEB_CONTENT.replace(b'orport=9001', b'orport=7814713228'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB (rueckgrat) has an invalid ORPort: 7814713228',
      FALLBACK_GITWEB_CONTENT.replace(b'ipv6=[2a01', b'ipv6=[:::'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB (rueckgrat) has an invalid IPv6 address: ::::4f8:162:51e2::2',
      FALLBACK_GITWEB_CONTENT.replace(b'nickname=rueckgrat', b'nickname=invalid~nickname'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB has an invalid nickname: invalid~nickname',
    }

    for entry, expected in test_values.items():
      with patch(URL_OPEN, Mock(return_value = io.BytesIO(entry))):
        self.assertRaisesRegexp(IOError, re.escape(expected), stem.directory.Fallback.from_remote)

  def test_persistence(self):
    expected = {
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB': stem.directory.Fallback(
        address = '5.9.110.236',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
        nickname = 'rueckgrat',
        has_extrainfo = True,
        orport_v6 = ('2a01:4f8:162:51e2::2', 9001),
        header = HEADER,
      ),
      '01A9258A46E97FF8B2CAC7910577862C14F2C524': stem.directory.Fallback(
        address = '193.171.202.146',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '01A9258A46E97FF8B2CAC7910577862C14F2C524',
        nickname = None,
        has_extrainfo = False,
        orport_v6 = None,
        header = HEADER,
      ),
    }

    excepted_config = {
      'tor_commit': ['abc'],
      'stem_commit': ['def'],
      'header.type': ['fallback'],
      'header.version': ['2.0.0'],
      'header.timestamp': ['20170526090242'],
      '01A9258A46E97FF8B2CAC7910577862C14F2C524.address': ['193.171.202.146'],
      '01A9258A46E97FF8B2CAC7910577862C14F2C524.or_port': ['9001'],
      '01A9258A46E97FF8B2CAC7910577862C14F2C524.dir_port': ['9030'],
      '01A9258A46E97FF8B2CAC7910577862C14F2C524.has_extrainfo': ['false'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.address': ['5.9.110.236'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.or_port': ['9001'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.dir_port': ['9030'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.nickname': ['rueckgrat'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.has_extrainfo': ['true'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.orport6_address': ['2a01:4f8:162:51e2::2'],
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB.orport6_port': ['9001'],
    }

    with tempfile.NamedTemporaryFile(prefix = 'fallbacks.') as tmp:
      stem.directory.Fallback._write(expected, 'abc', 'def', HEADER, tmp.name)

      conf = stem.util.conf.Config()
      conf.load(tmp.name)
      self.assertEqual(excepted_config, dict(conf))

      self.assertEqual(expected, stem.directory.Fallback.from_cache(tmp.name))
