"""
Unit tests for the stem.util.tor_tools functions.
"""

import unittest

import stem.util.tor_tools


class TestTorTools(unittest.TestCase):
  def test_is_valid_fingerprint(self):
    """
    Checks the is_valid_fingerprint function.
    """

    valid_fingerprints = (
      '$A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB',
      '$a7569a83b5706ab1b1a9cb52eff7d2d32e4553eb',
    )

    invalid_fingerprints = (
      '',
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
    )

    invalid_nicknames = (
      None,
      '',
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
