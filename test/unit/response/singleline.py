"""
Unit tests for the stem.response.SingleLineResponse class.
"""

import unittest

import stem.response
import stem.socket

from test import mocking

MULTILINE_RESPONSE = """250-MULTI
250 LINE"""


class TestSingleLineResponse(unittest.TestCase):
  def test_single_line_response(self):
    message = mocking.get_message('552 NOTOK')
    stem.response.convert('SINGLELINE', message)
    self.assertEqual(False, message.is_ok())

    message = mocking.get_message('250 KK')
    stem.response.convert('SINGLELINE', message)
    self.assertEqual(True, message.is_ok())

    message = mocking.get_message('250 OK')
    stem.response.convert('SINGLELINE', message)
    self.assertEqual(True, message.is_ok(True))

    message = mocking.get_message('250 HMM')
    stem.response.convert('SINGLELINE', message)
    self.assertEqual(False, message.is_ok(True))

  def test_multi_line_response(self):
    message = mocking.get_message(MULTILINE_RESPONSE)
    self.assertRaises(stem.ProtocolError, stem.response.convert, 'SINGLELINE', message)
