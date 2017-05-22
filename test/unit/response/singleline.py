"""
Unit tests for the stem.response.SingleLineResponse class.
"""

import unittest

import stem

from stem.response import ControlMessage


class TestSingleLineResponse(unittest.TestCase):
  def test_single_line_response(self):
    message = ControlMessage.from_str('552 NOTOK\r\n', 'SINGLELINE')
    self.assertEqual(False, message.is_ok())

    message = ControlMessage.from_str('250 KK\r\n', 'SINGLELINE')
    self.assertEqual(True, message.is_ok())

    message = ControlMessage.from_str('250 OK\r\n', 'SINGLELINE')
    self.assertEqual(True, message.is_ok(True))

    message = ControlMessage.from_str('250 HMM\r\n', 'SINGLELINE')
    self.assertEqual(False, message.is_ok(True))

  def test_multi_line_response(self):
    self.assertRaises(stem.ProtocolError, ControlMessage.from_str, '250-MULTI\r\n250 LINE\r\n', 'SINGLELINE')
