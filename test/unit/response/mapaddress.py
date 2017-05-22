"""
Unit tests for the stem.response.mapaddress.MapAddressResponse class.
"""

import unittest

import stem.response
import stem.response.mapaddress
import stem.socket

from stem.response import ControlMessage

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

    control_message = ControlMessage.from_str('250 foo=bar\r\n', 'MAPADDRESS')
    self.assertEqual({'foo': 'bar'}, control_message.entries)

  def test_batch_response(self):
    """
    Parses a MAPADDRESS reply with multiple address mappings
    """

    expected = {
      'foo': 'bar',
      'baz': 'quux',
      'gzzz': 'bzz',
      '120.23.23.2': 'torproject.org'
    }

    control_message = ControlMessage.from_str(BATCH_RESPONSE, 'MAPADDRESS', normalize = True)
    self.assertEqual(expected, control_message.entries)

  def test_invalid_requests(self):
    """
    Parses a MAPADDRESS replies that contain an error code due to hostname syntax errors.
    """

    control_message = ControlMessage.from_str(UNRECOGNIZED_KEYS_RESPONSE, normalize = True)
    self.assertRaises(stem.InvalidRequest, stem.response.convert, 'MAPADDRESS', control_message)

    control_message = ControlMessage.from_str(PARTIAL_FAILURE_RESPONSE, 'MAPADDRESS', normalize = True)
    self.assertEqual({'23': '324'}, control_message.entries)

  def test_invalid_response(self):
    """
    Parses a malformed MAPADDRESS reply that contains an invalid response code.
    This is a proper controller message, but malformed according to the
    MAPADDRESS's spec.
    """

    control_message = ControlMessage.from_str(INVALID_EMPTY_RESPONSE, normalize = True)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'MAPADDRESS', control_message)

    control_message = ControlMessage.from_str(INVALID_RESPONSE, normalize = True)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'MAPADDRESS', control_message)
