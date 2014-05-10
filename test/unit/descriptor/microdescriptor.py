"""
Unit tests for stem.descriptor.microdescriptor.
"""

import unittest

import stem.exit_policy

from stem.descriptor.microdescriptor import Microdescriptor
from test.mocking import get_microdescriptor, \
                         CRYPTO_BLOB


class TestMicrodescriptor(unittest.TestCase):
  def test_minimal_microdescriptor(self):
    """
    Basic sanity check that we can parse a microdescriptor with minimal
    attributes.
    """

    desc = get_microdescriptor()

    self.assertTrue(CRYPTO_BLOB in desc.onion_key)
    self.assertEquals(None, desc.ntor_onion_key)
    self.assertEquals([], desc.or_addresses)
    self.assertEquals([], desc.family)
    self.assertEquals(stem.exit_policy.MicroExitPolicy('reject 1-65535'), desc.exit_policy)
    self.assertEquals(None, desc.exit_policy_v6)
    self.assertEquals(None, desc.identifier_type)
    self.assertEquals(None, desc.identifier)
    self.assertEquals([], desc.get_unrecognized_lines())

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    desc = get_microdescriptor({'pepperjack': 'is oh so tasty!'})
    self.assertEquals(['pepperjack is oh so tasty!'], desc.get_unrecognized_lines())

  def test_proceeding_line(self):
    """
    Includes a line prior to the 'onion-key' entry.
    """

    desc_text = b'family Amunet1\n' + get_microdescriptor(content = True)
    self.assertRaises(ValueError, Microdescriptor, desc_text)

    desc = Microdescriptor(desc_text, validate = False)
    self.assertEquals(['Amunet1'], desc.family)

  def test_a_line(self):
    """
    Sanity test with both an IPv4 and IPv6 address.
    """

    desc_text = get_microdescriptor(content = True)
    desc_text += b'\na 10.45.227.253:9001'
    desc_text += b'\na [fd9f:2e19:3bcf::02:9970]:9001'

    expected = [
      ('10.45.227.253', 9001, False),
      ('fd9f:2e19:3bcf::02:9970', 9001, True),
    ]

    desc = Microdescriptor(desc_text)
    self.assertEquals(expected, desc.or_addresses)

  def test_family(self):
    """
    Check the family line.
    """

    desc = get_microdescriptor({'family': 'Amunet1 Amunet2 Amunet3'})
    self.assertEquals(['Amunet1', 'Amunet2', 'Amunet3'], desc.family)

    # try multiple family lines

    desc_text = get_microdescriptor(content = True)
    desc_text += b'\nfamily Amunet1'
    desc_text += b'\nfamily Amunet2'

    self.assertRaises(ValueError, Microdescriptor, desc_text)

    # family entries will overwrite each other
    desc = Microdescriptor(desc_text, validate = False)
    self.assertEquals(1, len(desc.family))

  def test_exit_policy(self):
    """
    Basic check for 'p' lines. The router status entries contain an identical
    field so we're not investing much effort here.
    """

    desc = get_microdescriptor({'p': 'accept 80,110,143,443'})
    self.assertEquals(stem.exit_policy.MicroExitPolicy('accept 80,110,143,443'), desc.exit_policy)

  def test_identifier(self):
    """
    Basic check for 'id' lines.
    """

    desc = get_microdescriptor({'id': 'rsa1024 Cd47okjCHD83YGzThGBDptXs9Z4'})
    self.assertEquals('rsa1024', desc.identifier_type)
    self.assertEquals('Cd47okjCHD83YGzThGBDptXs9Z4', desc.identifier)
