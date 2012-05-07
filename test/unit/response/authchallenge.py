"""
Unit tests for the stem.response.authchallenge.AuthChallengeResponse class.
"""

import unittest

import stem.socket
import stem.response
import stem.response.authchallenge
import test.mocking as mocking

class TestAuthChallengeResponse(unittest.TestCase):
  VALID_RESPONSE = "250 AUTHCHALLENGE SERVERHASH=B16F72DACD4B5ED1531F3FCC04B593D46A1E30267E636EA7C7F8DD7A2B7BAA05 SERVERNONCE=653574272ABBB49395BD1060D642D653CFB7A2FCE6A4955BCFED819703A9998C"
  VALID_HASH = "\xb1or\xda\xcdK^\xd1S\x1f?\xcc\x04\xb5\x93\xd4j\x1e0&~cn\xa7\xc7\xf8\xddz+{\xaa\x05"
  VALID_NONCE = "e5t'*\xbb\xb4\x93\x95\xbd\x10`\xd6B\xd6S\xcf\xb7\xa2\xfc\xe6\xa4\x95[\xcf\xed\x81\x97\x03\xa9\x99\x8c"
  INVALID_RESPONSE = "250 AUTHCHALLENGE SERVERHASH=FOOBARB16F72DACD4B5ED1531F3FCC04B593D46A1E30267E636EA7C7F8DD7A2B7BAA05 SERVERNONCE=FOOBAR653574272ABBB49395BD1060D642D653CFB7A2FCE6A4955BCFED819703A9998C"
  
  def test_valid_response(self):
    """
    Parses valid AUTHCHALLENGE responses.
    """
    
    control_message = mocking.get_message(self.VALID_RESPONSE)
    stem.response.convert("AUTHCHALLENGE", control_message)
    
    # now this should be a AuthChallengeResponse (ControlMessage subclass)
    self.assertTrue(isinstance(control_message, stem.response.ControlMessage))
    self.assertTrue(isinstance(control_message, stem.response.authchallenge.AuthChallengeResponse))
    
    self.assertEqual(self.VALID_HASH, control_message.server_hash)
    self.assertEqual(self.VALID_NONCE, control_message.server_nonce)
  
  def test_invalid_responses(self):
    """
    Tries to parse various malformed responses and checks it they raise
    appropriate exceptions.
    """
    
    valid_resp = self.VALID_RESPONSE.split()
    
    control_message = mocking.get_message(' '.join(valid_resp[0:1] + [valid_resp[3]]))
    self.assertRaises(stem.socket.ProtocolError, stem.response.convert, "AUTHCHALLENGE", control_message)
    
    control_message = mocking.get_message(' '.join(valid_resp[0:1] + [valid_resp[3], valid_resp[2]]))
    self.assertRaises(stem.socket.ProtocolError, stem.response.convert, "AUTHCHALLENGE", control_message)
    
    control_message = mocking.get_message(' '.join(valid_resp[0:2]))
    self.assertRaises(stem.socket.ProtocolError, stem.response.convert, "AUTHCHALLENGE", control_message)
    
    for begin in range(4):
      for end in range(4):
        try:
          control_message = mocking.get_message(' '.join(self.VALID_RESPONSE.split()[begin:end]))
        except stem.socket.ProtocolError:
          continue
        self.assertRaises(stem.socket.ProtocolError, stem.response.convert, "AUTHCHALLENGE", control_message)

