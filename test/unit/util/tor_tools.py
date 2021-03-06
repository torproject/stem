"""
Unit tests for the stem.util.tor_tools functions.
"""

import unittest

import stem.util.str_tools
import stem.util.tor_tools


class TestTorTools(unittest.TestCase):
  def test_is_valid_hidden_service_address_v2(self):
    """
    Checks the is_valid_hidden_service_address for v2 addresses.
    """

    valid_v2_addresses = [
      'facebookcorewwwi',
      'aaaaaaaaaaaaaaaa',
    ]

    invalid_v2_addresses = [
      'facebookcorewww',
      'facebookcorewwyi'
      'facebookc0rewwwi',
      'facebookcorew wi',
    ]

    for address in valid_v2_addresses:
      self.assertTrue(stem.util.tor_tools.is_valid_hidden_service_address(address))
      self.assertTrue(stem.util.tor_tools.is_valid_hidden_service_address(address, version = 2))

    for address in invalid_v2_addresses:
      self.assertFalse(stem.util.tor_tools.is_valid_hidden_service_address(address))
      self.assertFalse(stem.util.tor_tools.is_valid_hidden_service_address(address, version = 2))

  def test_is_valid_hidden_service_address_v3(self):
    """
    Checks the is_valid_hidden_service_address for v3 addresses.
    """

    valid_v3_addresses = [
      'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd',
      'sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd',
      'xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd',
    ]

    invalid_v3_addresses = [
      'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryc',  # bad version
      'xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jy',  # too short
      'sp3k262uwy4r2k4ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd',  # checksum mismatch
      'pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscrybd',  # too long
    ]

    for address in valid_v3_addresses:
      self.assertTrue(stem.util.tor_tools.is_valid_hidden_service_address(address))
      self.assertTrue(stem.util.tor_tools.is_valid_hidden_service_address(address, version = 3))

    for address in invalid_v3_addresses:
      self.assertFalse(stem.util.tor_tools.is_valid_hidden_service_address(address))
      self.assertFalse(stem.util.tor_tools.is_valid_hidden_service_address(address, version = 3))

  def test_is_valid_fingerprint(self):
    """
    Checks the is_valid_fingerprint function.
    """

    valid_fingerprints = (
      '$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB',
      '$a7569a83b5706ab1b1a9cb52eff7d2d32e4553eb',
      stem.util.str_tools._to_bytes('$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB'),
      stem.util.str_tools._to_unicode('$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB'),
    )

    invalid_fingerprints = (
      None,
      '',
      5,
      ['A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB'],
      'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB',
      '$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553E',
      '$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553E33',
      '$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EG',
    )

    for fingerprint in valid_fingerprints:
      self.assertTrue(stem.util.tor_tools.is_valid_fingerprint(fingerprint, True))

    for fingerprint in invalid_fingerprints:
      self.assertFalse(stem.util.tor_tools.is_valid_fingerprint(fingerprint, True))

  def test_is_valid_nickname(self):
    """
    Checks the is_valid_nickname function.
    """

    valid_nicknames = (
      'caerSidi',
      'a',
      'abcABC123',
      stem.util.str_tools._to_bytes('caerSidi'),
      stem.util.str_tools._to_unicode('caerSidi'),
    )

    invalid_nicknames = (
      None,
      '',
      5,
      'toolongggggggggggggg',
      'bad_character',
    )

    for nickname in valid_nicknames:
      self.assertTrue(stem.util.tor_tools.is_valid_nickname(nickname))

    for nickname in invalid_nicknames:
      self.assertFalse(stem.util.tor_tools.is_valid_nickname(nickname))

  def test_is_valid_circuit_id(self):
    """
    Checks the is_valid_circuit_id function.
    """

    valid_circuit_ids = (
      '0',
      '2',
      'abcABC123',
      stem.util.str_tools._to_bytes('2'),
      stem.util.str_tools._to_unicode('2'),
    )

    invalid_circuit_ids = (
      None,
      '',
      0,
      2,
      'toolonggggggggggg',
      'bad_character',
    )

    for circuit_id in valid_circuit_ids:
      self.assertTrue(stem.util.tor_tools.is_valid_circuit_id(circuit_id))

    for circuit_id in invalid_circuit_ids:
      self.assertFalse(stem.util.tor_tools.is_valid_circuit_id(circuit_id))

  def test_is_valid_hex_digits(self):
    """
    Checks the is_valid_hex_digits function.
    """

    valid_hex_digits = (
      '12345',
      'AbCdE',
      stem.util.str_tools._to_bytes('AbCdE'),
      stem.util.str_tools._to_unicode('AbCdE'),
    )

    invalid_hex_digits = (
      None,
      '',
      5,
      'X',
      '1234',
      'ABCDEF',
      [1, '2', (3, 4)]
    )

    for hex_digits in valid_hex_digits:
      self.assertTrue(stem.util.tor_tools.is_hex_digits(hex_digits, 5))

    for hex_digits in invalid_hex_digits:
      self.assertFalse(stem.util.tor_tools.is_hex_digits(hex_digits, 5))
