"""
Unit tests for the stem.response.mapaddress.MapAddressResponse class.
"""

import unittest

import stem.response
import stem.response.mapaddress
import stem.socket

from test import mocking

SINGLE_RESPONSE = """250 foo=bar"""

BATCH_RESPONSE = """\
250-foo=bar
250-baz=quux
250-gzzz=bzz
250 120.23.23.2=torproject.org"""

INVALID_EMPTY_RESPONSE = '250 OK'
INVALID_RESPONSE = '250 foo is bar'

PARTIAL_FAILURE_RESPONSE = """512-syntax error: mapping '2389' is not of expected form 'foo=bar'
512-syntax error: mapping '23' is not of expected form 'foo=bar'.
250 23=324"""

UNRECOGNIZED_KEYS_RESPONSE = "512 syntax error: mapping '2389' is not of expected form 'foo=bar'"

FAILED_RESPONSE = '451 Resource exhausted'


class TestMapAddressResponse(unittest.TestCase):
  def test_single_response(self):
    """
    Parses a MAPADDRESS reply response with a single address mapping.
    """

    control_message = mocking.get_message(SINGLE_RESPONSE)
    stem.response.convert('MAPADDRESS', control_message)
    self.assertEqual({'foo': 'bar'}, control_message.entries)

  def test_batch_response(self):
    """
    Parses a MAPADDRESS reply with multiple address mappings
    """

    control_message = mocking.get_message(BATCH_RESPONSE)
    stem.response.convert('MAPADDRESS', control_message)

    expected = {
      'foo': 'bar',
      'baz': 'quux',
      'gzzz': 'bzz',
      '120.23.23.2': 'torproject.org'
    }

    self.assertEqual(expected, control_message.entries)

  def test_invalid_requests(self):
    """
    Parses a MAPADDRESS replies that contain an error code due to hostname syntax errors.
    """

    control_message = mocking.get_message(UNRECOGNIZED_KEYS_RESPONSE)
    self.assertRaises(stem.InvalidRequest, stem.response.convert, 'MAPADDRESS', control_message)
    expected = {'23': '324'}

    control_message = mocking.get_message(PARTIAL_FAILURE_RESPONSE)
    stem.response.convert('MAPADDRESS', control_message)
    self.assertEqual(expected, control_message.entries)

  def test_invalid_response(self):
    """
    Parses a malformed MAPADDRESS reply that contains an invalid response code.
    This is a proper controller message, but malformed according to the
    MAPADDRESS's spec.
    """

    control_message = mocking.get_message(INVALID_EMPTY_RESPONSE)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'MAPADDRESS', control_message)

    control_message = mocking.get_message(INVALID_RESPONSE)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'MAPADDRESS', control_message)
