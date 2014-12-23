"""
Unit tests for the stem.response.authchallenge.AuthChallengeResponse class.
"""

import unittest

import stem.response
import stem.response.authchallenge
import stem.socket

from test import mocking

VALID_RESPONSE = '250 AUTHCHALLENGE \
SERVERHASH=B16F72DACD4B5ED1531F3FCC04B593D46A1E30267E636EA7C7F8DD7A2B7BAA05 \
SERVERNONCE=653574272ABBB49395BD1060D642D653CFB7A2FCE6A4955BCFED819703A9998C'

VALID_HASH = b'\xb1or\xda\xcdK^\xd1S\x1f?\xcc\x04\xb5\x93\xd4j\x1e0&~cn\xa7\xc7\xf8\xddz+{\xaa\x05'
VALID_NONCE = b"e5t'*\xbb\xb4\x93\x95\xbd\x10`\xd6B\xd6S\xcf\xb7\xa2\xfc\xe6\xa4\x95[\xcf\xed\x81\x97\x03\xa9\x99\x8c"
INVALID_RESPONSE = '250 AUTHCHALLENGE \
SERVERHASH=FOOBARB16F72DACD4B5ED1531F3FCC04B593D46A1E30267E636EA7C7F8DD7A2B7BAA05 \
SERVERNONCE=FOOBAR653574272ABBB49395BD1060D642D653CFB7A2FCE6A4955BCFED819703A9998C'


class TestAuthChallengeResponse(unittest.TestCase):
  def test_valid_response(self):
    """
    Parses valid AUTHCHALLENGE responses.
    """

    control_message = mocking.get_message(VALID_RESPONSE)
    stem.response.convert('AUTHCHALLENGE', control_message)

    # now this should be a AuthChallengeResponse (ControlMessage subclass)
    self.assertTrue(isinstance(control_message, stem.response.ControlMessage))
    self.assertTrue(isinstance(control_message, stem.response.authchallenge.AuthChallengeResponse))

    self.assertEqual(VALID_HASH, control_message.server_hash)
    self.assertEqual(VALID_NONCE, control_message.server_nonce)

  def test_invalid_responses(self):
    """
    Tries to parse various malformed responses and checks it they raise
    appropriate exceptions.
    """

    auth_challenge_comp = VALID_RESPONSE.split()

    for index in range(1, len(auth_challenge_comp)):
      # Attempts to parse a message without this item. The first item is
      # skipped because, without the 250 code, the message won't be
      # constructed.

      remaining_comp = auth_challenge_comp[:index] + auth_challenge_comp[index + 1:]
      control_message = mocking.get_message(' '.join(remaining_comp))
      self.assertRaises(stem.ProtocolError, stem.response.convert, 'AUTHCHALLENGE', control_message)
