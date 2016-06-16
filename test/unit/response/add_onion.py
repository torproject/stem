"""
Unit tests for the stem.response.add_onion.AddOnionResponse class.
"""

import unittest

import stem
import stem.response
import stem.response.add_onion

from test import mocking

WITH_PRIVATE_KEY = """250-ServiceID=gfzprpioee3hoppz
250-PrivateKey=RSA1024:MIICXgIBAAKBgQDZvYVxvKPTWhId/8Ss9fVxjAoFDsrJ3pk6HjHrEFRm3ypkK/vArbG9BrupzzYcyms+lO06O8b/iOSHuZI5mUEGkrYqQ+hpB2SkPUEzW7vcp8SQQivna3+LfkWH4JDqfiwZutU6MMEvU6g1OqK4Hll6uHbLpsfxkS/mGjyu1C9a9wIDAQABAoGBAJxsC3a25xZJqaRFfxwmIiptSTFy+/nj4T4gPQo6k/fHMKP/+P7liT9bm+uUwbITNNIjmPzxvrcKt+pNRR/92fizxr8QXr8l0ciVOLerbvdqvVUaQ/K1IVsblOLbactMvXcHactmqqLFUaZU9PPSDla7YkzikLDIUtHXQBEt4HEhAkEA/c4n+kpwi4odCaF49ESPbZC/Qejh7U9Tq10vAHzfrrGgQjnLw2UGDxJQXc9P12fGTvD2q3Q3VaMI8TKKFqZXsQJBANufh1zfP+xX/UfxJ4QzDUCHCu2gnyTDj3nG9Bc80E5g7NwR2VBXF1R+QQCK9GZcXd2y6vBYgrHOSUiLbVjGrycCQQDpOcs0zbjUEUuTsQUT+fiO50dJSrZpus6ZFxz85sMppeItWSzsVeYWbW7adYnZ2Gu72OPjM/0xPYsXEakhHSRRAkAxlVauNQjthv/72god4pi/VL224GiNmEkwKSa6iFRPHbrcBHuXk9IElWx/ft+mrHvUraw1DwaStgv9gNzzCghJAkEA08RegCRnIzuGvgeejLk4suIeCMD/11AvmSvxbRWS5rq1leSVo7uGLSnqDbwlzE4dGb5kH15NNAp14/l2Fu/yZg==
250 OK"""

WITH_CLIENT_AUTH = """250-ServiceID=oekn5sqrvcu4wote
250-ClientAuth=bob:lhwLVFt0Kd5/0Gy9DkKoyA
250-ClientAuth=alice:T9UADxtrvqx2HnLKWp/fWQ
250 OK
"""

WITHOUT_PRIVATE_KEY = """250-ServiceID=gfzprpioee3hoppz
250 OK"""

WRONG_FIRST_KEY = """250-MyKey=gfzprpioee3hoppz
250-ServiceID=gfzprpioee3hoppz
250 OK"""

MISSING_KEY_TYPE = """250-ServiceID=gfzprpioee3hoppz
250-PrivateKey=MIICXgIBAAKBgQDZvYVxvKPTWhId/8Ss9fVxj
250 OK"""


class TestAddOnionResponse(unittest.TestCase):
  def test_convert(self):
    """
    Exercises functionality of the convert method both when it works and
    there's an error.
    """

    # working case
    response = mocking.get_message(WITH_PRIVATE_KEY)
    stem.response.convert('ADD_ONION', response)

    # now this should be a AddOnionResponse (ControlMessage subclass)
    self.assertTrue(isinstance(response, stem.response.ControlMessage))
    self.assertTrue(isinstance(response, stem.response.add_onion.AddOnionResponse))

    # exercise some of the ControlMessage functionality
    raw_content = (WITH_PRIVATE_KEY + '\n').replace('\n', '\r\n')
    self.assertEqual(raw_content, response.raw_content())
    self.assertTrue(str(response).startswith('ServiceID='))

  def test_with_private_key(self):
    """
    Checks a response when there's a private key.
    """

    response = mocking.get_message(WITH_PRIVATE_KEY)
    stem.response.convert('ADD_ONION', response)

    self.assertEqual('gfzprpioee3hoppz', response.service_id)
    self.assertTrue(response.private_key.startswith('MIICXgIBAAKB'))
    self.assertEqual('RSA1024', response.private_key_type)
    self.assertEqual({}, response.client_auth)

  def test_with_client_auth(self):
    """
    Checks a response when there's client credentials.
    """

    response = mocking.get_message(WITH_CLIENT_AUTH)
    stem.response.convert('ADD_ONION', response)

    self.assertEqual('oekn5sqrvcu4wote', response.service_id)
    self.assertEqual(None, response.private_key)
    self.assertEqual(None, response.private_key_type)
    self.assertEqual({'bob': 'lhwLVFt0Kd5/0Gy9DkKoyA', 'alice': 'T9UADxtrvqx2HnLKWp/fWQ'}, response.client_auth)

  def test_without_private_key(self):
    """
    Checks a response without a private key.
    """

    response = mocking.get_message(WITHOUT_PRIVATE_KEY)
    stem.response.convert('ADD_ONION', response)

    self.assertEqual('gfzprpioee3hoppz', response.service_id)
    self.assertEqual(None, response.private_key)
    self.assertEqual(None, response.private_key_type)

  def test_without_service_id(self):
    """
    Checks a response that lack an initial service id.
    """

    try:
      response = mocking.get_message(WRONG_FIRST_KEY)
      stem.response.convert('ADD_ONION', response)
      self.fail("we should've raised a ProtocolError")
    except stem.ProtocolError as exc:
      self.assertTrue(str(exc).startswith('ADD_ONION response should start with'))

  def test_no_key_type(self):
    """
    Checks a response that's missing the private key type.
    """

    try:
      response = mocking.get_message(MISSING_KEY_TYPE)
      stem.response.convert('ADD_ONION', response)
      self.fail("we should've raised a ProtocolError")
    except stem.ProtocolError as exc:
      self.assertTrue(str(exc).startswith('ADD_ONION PrivateKey lines should be of the form'))
