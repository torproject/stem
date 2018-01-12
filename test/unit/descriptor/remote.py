"""
Unit tests for stem.descriptor.remote.
"""

import io
import socket
import tempfile
import unittest

import stem.descriptor.remote
import stem.prereq
import stem.util.conf

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

try:
  # added in python 3.3
  from unittest.mock import patch
except ImportError:
  from mock import patch

# The urlopen() method is in a different location depending on if we're using
# python 2.x or 3.x. The 2to3 converter accounts for this in imports, but not
# mock annotations.

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'

# Output from requesting moria1's descriptor from itself...
# % curl http://128.31.0.39:9131/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31

TEST_DESCRIPTOR = b"""\
router moria1 128.31.0.34 9101 0 9131
platform Tor 0.2.5.0-alpha-dev on Linux
protocols Link 1 2 Circuit 1
published 2013-07-05 23:48:52
fingerprint 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31
uptime 1818933
bandwidth 512000 62914560 1307929
extra-info-digest 17D0142F6EBCDF60160EB1794FA6C9717D581F8C
caches-extra-info
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALzd4bhz1usB7wpoaAvP+BBOnNIk7mByAKV6zvyQ0p1M09oEmxPMc3qD
AAm276oJNf0eq6KWC6YprzPWFsXEIdXSqA6RWXCII1JG/jOoy6nt478BkB8TS9I9
1MJW27ppRaqnLiTmBmM+qzrsgJGwf+onAgUKKH2GxlVgahqz8x6xAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALtJ9uD7cD7iHjqNA3AgsX9prES5QN+yFQyr2uOkxzhvunnaf6SNhzWW
bkfylnMrRm/qCz/czcjZO6N6EKHcXmypehvP566B7gAQ9vDsb+l7VZVWgXvzNc2s
tl3P7qpC08rgyJh1GqmtQTCesIDqkEyWxwToympCt09ZQRq+fIttAgMBAAE=
-----END RSA PUBLIC KEY-----
hidden-service-dir
contact 1024D/28988BF5 arma mit edu
ntor-onion-key 9ZVjNkf/iLEnD685SpC5kcDytQ7u5ViiI9JOftdbE0k=
reject *:*
router-signature
-----BEGIN SIGNATURE-----
Y8Tj2e7mPbFJbguulkPEBVYzyO57p4btpWEXvRMD6vxIh/eyn25pehg5dUVBtZlL
iO3EUE0AEYah2W9gdz8t+i3Dtr0zgqLS841GC/TyDKCm+MKmN8d098qnwK0NGF9q
01NZPuSqXM1b6hnl2espFzL7XL8XEGRU+aeg+f/ukw4=
-----END SIGNATURE-----
"""

FALLBACK_DIR_CONTENT = b"""\
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

FALLBACK_ENTRY = b"""\
"5.9.110.236:9030 orport=9001 id=0756B7CD4DFC8182BE23143FAC0642F515182CEB"
" ipv6=[2a01:4f8:162:51e2::2]:9001"
/* nickname=rueckgrat */
/* extrainfo=1 */
"""


class TestDescriptorDownloader(unittest.TestCase):
  @patch(URL_OPEN)
  def test_query_download(self, urlopen_mock):
    """
    Check Query functionality when we successfully download a descriptor.
    """

    urlopen_mock.return_value = io.BytesIO(TEST_DESCRIPTOR)

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      validate = True,
    )

    expeced_url = 'http://128.31.0.39:9131/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31'
    self.assertEqual(expeced_url, query._pick_url())

    descriptors = list(query)
    self.assertEqual(1, len(descriptors))
    desc = descriptors[0]

    self.assertEqual('moria1', desc.nickname)
    self.assertEqual('128.31.0.34', desc.address)
    self.assertEqual('9695DFC35FFEB861329B9F1AB04C46397020CE31', desc.fingerprint)
    self.assertEqual(TEST_DESCRIPTOR.strip(), desc.get_bytes())

    urlopen_mock.assert_called_once_with(expeced_url, timeout = None)

  @patch(URL_OPEN)
  def test_query_with_malformed_content(self, urlopen_mock):
    """
    Query with malformed descriptor content.
    """

    descriptor_content = b'some malformed stuff'
    urlopen_mock.return_value = io.BytesIO(descriptor_content)

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      validate = True,
    )

    # checking via the iterator

    expected_error_msg = 'Content conform to being a server descriptor:\nsome malformed stuff'

    descriptors = list(query)
    self.assertEqual(0, len(descriptors))
    self.assertEqual(ValueError, type(query.error))
    self.assertEqual(expected_error_msg, str(query.error))

    # check via the run() method

    self.assertRaises(ValueError, query.run)

  @patch(URL_OPEN)
  def test_query_with_timeout(self, urlopen_mock):
    urlopen_mock.side_effect = socket.timeout('connection timed out')

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      fall_back_to_authority = False,
      timeout = 5,
      validate = True,
    )

    self.assertRaises(socket.timeout, query.run)
    urlopen_mock.assert_called_with(
      'http://128.31.0.39:9131/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      timeout = 5,
    )
    self.assertEqual(3, urlopen_mock.call_count)

  @patch(URL_OPEN)
  def test_can_iterate_multiple_times(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO(TEST_DESCRIPTOR)

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      validate = True,
    )

    # check that iterating over the query provides the descriptors each time

    self.assertEqual(1, len(list(query)))
    self.assertEqual(1, len(list(query)))
    self.assertEqual(1, len(list(query)))

  def test_using_authorities_in_hash(self):
    # ensure our DirectoryAuthority instances can be used in hashes
    {stem.descriptor.remote.get_authorities()['moria1']: 'hello'}

  def test_fallback_directories_from_cache(self):
    # quick sanity test that we can load cached content
    fallback_directories = stem.descriptor.remote.FallbackDirectory.from_cache()
    self.assertTrue(len(fallback_directories) > 10)
    self.assertEqual('5.39.92.199', fallback_directories['0BEA4A88D069753218EAAAD6D22EA87B9A1319D6'].address)

  @patch(URL_OPEN)
  def test_fallback_directories_from_remote(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO(FALLBACK_DIR_CONTENT)
    fallback_directories = stem.descriptor.remote.FallbackDirectory.from_remote()
    header = OrderedDict((('type', 'fallback'), ('version', '2.0.0'), ('timestamp', '20170526090242')))

    expected = {
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB': stem.descriptor.remote.FallbackDirectory(
        address = '5.9.110.236',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
        nickname = 'rueckgrat',
        has_extrainfo = True,
        orport_v6 = ('2a01:4f8:162:51e2::2', 9001),
        header = header,
      ),
      '01A9258A46E97FF8B2CAC7910577862C14F2C524': stem.descriptor.remote.FallbackDirectory(
        address = '193.171.202.146',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '01A9258A46E97FF8B2CAC7910577862C14F2C524',
        nickname = None,
        has_extrainfo = False,
        orport_v6 = None,
        header = header,
      ),
    }

    self.assertEqual(expected, fallback_directories)

  def test_fallback_persistence(self):
    header = OrderedDict((('type', 'fallback'), ('version', '2.0.0'), ('timestamp', '20170526090242')))

    expected = {
      '0756B7CD4DFC8182BE23143FAC0642F515182CEB': stem.descriptor.remote.FallbackDirectory(
        address = '5.9.110.236',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
        nickname = 'rueckgrat',
        has_extrainfo = True,
        orport_v6 = ('2a01:4f8:162:51e2::2', 9001),
        header = header,
      ),
      '01A9258A46E97FF8B2CAC7910577862C14F2C524': stem.descriptor.remote.FallbackDirectory(
        address = '193.171.202.146',
        or_port = 9001,
        dir_port = 9030,
        fingerprint = '01A9258A46E97FF8B2CAC7910577862C14F2C524',
        nickname = None,
        has_extrainfo = False,
        orport_v6 = None,
        header = header,
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
      stem.descriptor.remote.FallbackDirectory._write(expected, 'abc', 'def', header, tmp.name)

      conf = stem.util.conf.Config()
      conf.load(tmp.name)
      self.assertEqual(excepted_config, dict(conf))

      self.assertEqual(expected, stem.descriptor.remote.FallbackDirectory.from_cache(tmp.name))

  @patch(URL_OPEN)
  def test_fallback_directories_from_remote_empty(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO('')
    self.assertRaisesRegexp(IOError, 'did not have any content', stem.descriptor.remote.FallbackDirectory.from_remote)

  @patch(URL_OPEN)
  def test_fallback_directories_from_remote_no_header(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO('\n'.join(FALLBACK_DIR_CONTENT.splitlines()[1:]))
    self.assertRaisesRegexp(IOError, 'does not have a type field indicating it is fallback directory metadata', stem.descriptor.remote.FallbackDirectory.from_remote)

  @patch(URL_OPEN)
  def test_fallback_directories_from_remote_malformed_header(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO(FALLBACK_DIR_CONTENT.replace('version=2.0.0', 'version'))
    self.assertRaisesRegexp(IOError, 'Malformed fallback directory header line: /\* version \*/', stem.descriptor.remote.FallbackDirectory.from_remote)

  def test_fallback_directories_from_str(self):
    expected = stem.descriptor.remote.FallbackDirectory(
      address = '5.9.110.236',
      or_port = 9001,
      dir_port = 9030,
      fingerprint = '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
      nickname = 'rueckgrat',
      has_extrainfo = True,
      orport_v6 = ('2a01:4f8:162:51e2::2', 9001),
    )

    self.assertEqual(expected, stem.descriptor.remote.FallbackDirectory.from_str(FALLBACK_ENTRY))

  def test_fallback_directories_from_str_malformed(self):
    test_values = {
      FALLBACK_ENTRY.replace('id=0756B7CD4DFC8182BE23143FAC0642F515182CEB', ''): 'Malformed fallback address line:',
      FALLBACK_ENTRY.replace('5.9.110.236', '5.9.110'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB has an invalid IPv4 address: 5.9.110',
      FALLBACK_ENTRY.replace(':9030', ':7814713228'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB has an invalid dir_port: 7814713228',
      FALLBACK_ENTRY.replace('orport=9001', 'orport=7814713228'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB has an invalid or_port: 7814713228',
      FALLBACK_ENTRY.replace('ipv6=[2a01', 'ipv6=[:::'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB has an invalid IPv6 address: ::::4f8:162:51e2::2',
      FALLBACK_ENTRY.replace('nickname=rueckgrat', 'nickname=invalid~nickname'): '0756B7CD4DFC8182BE23143FAC0642F515182CEB has an invalid nickname: invalid~nickname',
    }

    for entry, expected in test_values.items():
      self.assertRaisesRegexp(ValueError, expected, stem.descriptor.remote.FallbackDirectory.from_str, entry)
