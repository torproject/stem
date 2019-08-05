"""
Unit tests for stem.directory.Authority.
"""

import io
import unittest

import stem
import stem.directory
import stem.prereq

try:
  # added in python 3.3
  from unittest.mock import patch, Mock
except ImportError:
  from mock import patch, Mock

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'

AUTHORITY_GITWEB_CONTENT = b"""\
"moria1 orport=9101 "
  "v3ident=D586D18309DED4CD6D57C18FDB97EFA96D330566 "
  "128.31.0.39:9131 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31",
"tor26 orport=443 "
  "v3ident=14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
  "ipv6=[2001:858:2:2:aabb:0:563b:1526]:443 "
  "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
"""


class TestAuthority(unittest.TestCase):
  def test_equality(self):
    authority_attr = {
      'address': '5.9.110.236',
      'or_port': 9001,
      'dir_port': 9030,
      'fingerprint': '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
      'nickname': 'rueckgrat',
      'orport_v6': ('2a01:4f8:162:51e2::2', 9001),
      'v3ident': '23D15D965BC35114467363C165C4F724B64B4F66',
    }

    self.assertEqual(stem.directory.Authority(**authority_attr), stem.directory.Authority(**authority_attr))

    for attr in authority_attr:
      for value in (None, 'something else'):
        second_authority = stem.directory.Authority(**authority_attr)
        setattr(second_authority, attr, value)
        self.assertNotEqual(stem.directory.Authority(**authority_attr), second_authority)

  def test_from_cache(self):
    authorities = stem.directory.Authority.from_cache()
    self.assertTrue(len(authorities) > 4)
    self.assertEqual('128.31.0.39', authorities['moria1'].address)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(AUTHORITY_GITWEB_CONTENT)))
  def test_from_remote(self):
    expected = {
      'moria1': stem.directory.Authority(
        nickname = 'moria1',
        address = '128.31.0.39',
        or_port = 9101,
        dir_port = 9131,
        fingerprint = '9695DFC35FFEB861329B9F1AB04C46397020CE31',
        v3ident = 'D586D18309DED4CD6D57C18FDB97EFA96D330566',
      ),
      'tor26': stem.directory.Authority(
        nickname = 'tor26',
        address = '86.59.21.38',
        or_port = 443,
        dir_port = 80,
        fingerprint = '847B1F850344D7876491A54892F904934E4EB85D',
        orport_v6 = ('2001:858:2:2:aabb:0:563b:1526', 443),
        v3ident = '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
      ),
    }

    self.assertEqual(expected, stem.directory.Authority.from_remote())

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'')))
  def test_from_remote_empty(self):
    self.assertRaisesRegexp(stem.DownloadFailed, 'no content', stem.directory.Authority.from_remote)
