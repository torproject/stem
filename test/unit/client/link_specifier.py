"""
Unit tests for stem.client.datatype.LinkSpecifier and subclasses.
"""

import unittest

from stem.client.datatype import (
  LinkSpecifier,
  LinkByIPv4,
  LinkByIPv6,
  LinkByFingerprint,
  LinkByEd25519,
)


class TestLinkSpecifier(unittest.TestCase):
  def test_link_by_ipv4_address(self):
    destination = LinkSpecifier.unpack(b'\x00\x06\x01\x02\x03\x04#)')

    self.assertEqual(LinkByIPv4, type(destination))
    self.assertEqual(0, destination.type)
    self.assertEqual(b'\x01\x02\x03\x04#)', destination.value)
    self.assertEqual('1.2.3.4', destination.address)
    self.assertEqual(9001, destination.port)

    destination = LinkByIPv4('1.2.3.4', 9001)
    self.assertEqual(b'\x00\x06\x01\x02\x03\x04#)', destination.pack())
    self.assertEqual(b'\x01\x02\x03\x04#)', destination.value)

  def test_link_by_ipv6_address(self):
    destination, _ = LinkSpecifier.pop(b'\x01\x12&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)')

    self.assertEqual(LinkByIPv6, type(destination))
    self.assertEqual(1, destination.type)
    self.assertEqual(b'&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)', destination.value)
    self.assertEqual('2600:0000:0000:0000:0000:0000:0000:0001', destination.address)
    self.assertEqual(9001, destination.port)

    destination = LinkByIPv6('2600:0000:0000:0000:0000:0000:0000:0001', 9001)
    self.assertEqual(b'\x01\x12&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)', destination.pack())
    self.assertEqual(b'&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)', destination.value)

  def test_link_by_fingerprint(self):
    destination, _ = LinkSpecifier.pop(b'\x02\x14CCCCCCCCCCCCCCCCCCCC')

    self.assertEqual(LinkByFingerprint, type(destination))
    self.assertEqual(2, destination.type)
    self.assertEqual(b'CCCCCCCCCCCCCCCCCCCC', destination.value)
    self.assertEqual('CCCCCCCCCCCCCCCCCCCC', destination.fingerprint)

  def test_link_by_ed25519fingerprint(self):
    destination, _ = LinkSpecifier.pop(b'\x03\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC')

    self.assertEqual(LinkByEd25519, type(destination))
    self.assertEqual(3, destination.type)
    self.assertEqual(b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', destination.value)
    self.assertEqual('CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', destination.fingerprint)

  def test_unrecognized_type(self):
    destination, _ = LinkSpecifier.pop(b'\x04\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC')

    self.assertEqual(LinkSpecifier, type(destination))
    self.assertEqual(4, destination.type)
    self.assertEqual(b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC', destination.value)

  def test_wrong_size(self):
    self.assertRaisesWith(ValueError, 'Link specifier should have 32 bytes, but only had 7 remaining', LinkSpecifier.pop, b'\x04\x20CCCCCCC')

  def test_pack(self):
    test_inputs = (
      b'\x03\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      b'\x04\x20CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
      b'\x01\x12&\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01#)',
      b'\x00\x06\x01\x02\x03\x04#)',
    )

    for val in test_inputs:
      destination, _ = LinkSpecifier.pop(val)
      self.assertEqual(val, destination.pack())
