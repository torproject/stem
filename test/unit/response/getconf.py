"""
Unit tests for the stem.response.getconf.GetConfResponse class.
"""

import unittest

import stem.response
import stem.response.getconf
import stem.socket

from test import mocking

EMPTY_RESPONSE = '250 OK'

SINGLE_RESPONSE = """\
250 DataDirectory=/home/neena/.tor"""

BATCH_RESPONSE = """\
250-CookieAuthentication=0
250-ControlPort=9100
250-DataDirectory=/tmp/fake dir
250 DirPort"""

MULTIVALUE_RESPONSE = """\
250-ControlPort=9100
250-ExitPolicy=accept 34.3.4.5
250-ExitPolicy=accept 3.4.53.3
250-ExitPolicy=accept 3.4.53.3
250 ExitPolicy=reject 23.245.54.3"""

UNRECOGNIZED_KEY_RESPONSE = '''552-Unrecognized configuration key "brickroad"
552 Unrecognized configuration key "submarine"'''

INVALID_RESPONSE = """\
123-FOO
232 BAR"""


class TestGetConfResponse(unittest.TestCase):
  def test_empty_response(self):
    """
    Parses a GETCONF reply without options (just calling "GETCONF").
    """

    control_message = mocking.get_message(EMPTY_RESPONSE)
    stem.response.convert('GETCONF', control_message)

    # now this should be a GetConfResponse (ControlMessage subclass)
    self.assertTrue(isinstance(control_message, stem.response.ControlMessage))
    self.assertTrue(isinstance(control_message, stem.response.getconf.GetConfResponse))

    self.assertEqual({}, control_message.entries)

  def test_single_response(self):
    """
    Parses a GETCONF reply response for a single parameter.
    """

    control_message = mocking.get_message(SINGLE_RESPONSE)
    stem.response.convert('GETCONF', control_message)
    self.assertEqual({'DataDirectory': ['/home/neena/.tor']}, control_message.entries)

  def test_batch_response(self):
    """
    Parses a GETCONF reply for muiltiple parameters.
    """

    control_message = mocking.get_message(BATCH_RESPONSE)
    stem.response.convert('GETCONF', control_message)

    expected = {
      'CookieAuthentication': ['0'],
      'ControlPort': ['9100'],
      'DataDirectory': ['/tmp/fake dir'],
      'DirPort': [],
    }

    self.assertEqual(expected, control_message.entries)

  def test_multivalue_response(self):
    """
    Parses a GETCONF reply containing a single key with multiple parameters.
    """

    control_message = mocking.get_message(MULTIVALUE_RESPONSE)
    stem.response.convert('GETCONF', control_message)

    expected = {
      'ControlPort': ['9100'],
      'ExitPolicy': ['accept 34.3.4.5', 'accept 3.4.53.3', 'accept 3.4.53.3', 'reject 23.245.54.3']
    }

    self.assertEqual(expected, control_message.entries)

  def test_unrecognized_key_response(self):
    """
    Parses a GETCONF reply that contains an error code with an unrecognized key.
    """

    control_message = mocking.get_message(UNRECOGNIZED_KEY_RESPONSE)
    self.assertRaises(stem.InvalidArguments, stem.response.convert, 'GETCONF', control_message)

    try:
      stem.response.convert('GETCONF', control_message)
    except stem.InvalidArguments as exc:
      self.assertEqual(exc.arguments, ['brickroad', 'submarine'])

  def test_invalid_content(self):
    """
    Parses a malformed GETCONF reply that contains an invalid response code.
    This is a proper controller message, but malformed according to the
    GETCONF's spec.
    """

    control_message = mocking.get_message(INVALID_RESPONSE)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'GETCONF', control_message)
