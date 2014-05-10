"""
Unit tests for the stem.response.getinfo.GetInfoResponse class.
"""

import unittest

import stem.response
import stem.response.getinfo
import stem.socket
import stem.util.str_tools

from test import mocking

EMPTY_RESPONSE = '250 OK'

SINGLE_RESPONSE = """\
250-version=0.2.3.11-alpha-dev
250 OK"""

BATCH_RESPONSE = """\
250-version=0.2.3.11-alpha-dev
250-address=67.137.76.214
250-fingerprint=5FDE0422045DF0E1879A3738D09099EB4A0C5BA0
250 OK"""

MULTILINE_RESPONSE = """\
250-version=0.2.3.11-alpha-dev (git-ef0bc7f8f26a917c)
250+config-text=
ControlPort 9051
DataDirectory /home/atagar/.tor
ExitPolicy reject *:*
Log notice stdout
Nickname Unnamed
ORPort 9050
.
250 OK"""

NON_KEY_VALUE_ENTRY = """\
250-version=0.2.3.11-alpha-dev
250-address 67.137.76.214
250 OK"""

UNRECOGNIZED_KEY_ENTRY = """\
552 Unrecognized key "blackhole"
"""

MISSING_MULTILINE_NEWLINE = """\
250+config-text=ControlPort 9051
DataDirectory /home/atagar/.tor
.
250 OK"""


class TestGetInfoResponse(unittest.TestCase):
  def test_empty_response(self):
    """
    Parses a GETINFO reply without options (just calling "GETINFO").
    """

    control_message = mocking.get_message(EMPTY_RESPONSE)
    stem.response.convert('GETINFO', control_message)

    # now this should be a GetInfoResponse (ControlMessage subclass)
    self.assertTrue(isinstance(control_message, stem.response.ControlMessage))
    self.assertTrue(isinstance(control_message, stem.response.getinfo.GetInfoResponse))

    self.assertEqual({}, control_message.entries)

  def test_single_response(self):
    """
    Parses a GETINFO reply response for a single parameter.
    """

    control_message = mocking.get_message(SINGLE_RESPONSE)
    stem.response.convert('GETINFO', control_message)
    self.assertEqual({'version': b'0.2.3.11-alpha-dev'}, control_message.entries)

  def test_batch_response(self):
    """
    Parses a GETINFO reply for muiltiple parameters.
    """

    control_message = mocking.get_message(BATCH_RESPONSE)
    stem.response.convert('GETINFO', control_message)

    expected = {
      'version': b'0.2.3.11-alpha-dev',
      'address': b'67.137.76.214',
      'fingerprint': b'5FDE0422045DF0E1879A3738D09099EB4A0C5BA0',
    }

    self.assertEqual(expected, control_message.entries)

  def test_multiline_response(self):
    """
    Parses a GETINFO reply for multiple parameters including a multi-line
    value.
    """

    control_message = mocking.get_message(MULTILINE_RESPONSE)
    stem.response.convert('GETINFO', control_message)

    expected = {
      'version': b'0.2.3.11-alpha-dev (git-ef0bc7f8f26a917c)',
      'config-text': b'\n'.join(stem.util.str_tools._to_bytes(MULTILINE_RESPONSE).splitlines()[2:8]),
    }

    self.assertEqual(expected, control_message.entries)

  def test_invalid_non_mapping_content(self):
    """
    Parses a malformed GETINFO reply containing a line that isn't a key=value
    entry.
    """

    control_message = mocking.get_message(NON_KEY_VALUE_ENTRY)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'GETINFO', control_message)

  def test_unrecognized_key_response(self):
    """
    Parses a GETCONF reply that contains an error code with an unrecognized key.
    """

    control_message = mocking.get_message(UNRECOGNIZED_KEY_ENTRY)
    self.assertRaises(stem.InvalidArguments, stem.response.convert, 'GETINFO', control_message)

    try:
      stem.response.convert('GETINFO', control_message)
    except stem.InvalidArguments as exc:
      self.assertEqual(exc.arguments, ['blackhole'])

  def test_invalid_multiline_content(self):
    """
    Parses a malformed GETINFO reply with a multi-line entry missing a newline
    between its key and value. This is a proper controller message, but
    malformed according to the GETINFO's spec.
    """

    control_message = mocking.get_message(MISSING_MULTILINE_NEWLINE)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'GETINFO', control_message)
