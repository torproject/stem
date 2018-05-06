"""
Unit tests for stem.directory.Authority.
"""

import unittest

import stem.directory


class TestAuthority(unittest.TestCase):
  def test_equality(self):
    authority_attr = {
      'address': '5.9.110.236',
      'or_port': 9001,
      'dir_port': 9030,
      'fingerprint': '0756B7CD4DFC8182BE23143FAC0642F515182CEB',
      'nickname': 'rueckgrat',
      'v3ident': '23D15D965BC35114467363C165C4F724B64B4F66',
      'is_bandwidth_authority': False,
    }

    self.assertEqual(stem.directory.Authority(**authority_attr), stem.directory.Authority(**authority_attr))

    for attr in authority_attr:
      for value in (None, 'something else'):
        second_authority = dict(authority_attr)
        second_authority[attr] = value
        self.assertNotEqual(stem.directory.Authority(**authority_attr), stem.directory.Authority(**second_authority))
