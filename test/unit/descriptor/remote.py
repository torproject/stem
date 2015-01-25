"""
Unit tests for stem.descriptor.remote.
"""

import io
import socket
import unittest

import stem.prereq
import stem.descriptor.remote

try:
  # added in python 3.3
  from unittest.mock import patch
except ImportError:
  from mock import patch

# The urlopen() method is in a different location depending on if we're using
# python 2.x or 3.x. The 2to3 converter accounts for this in imports, but not
# mock annotations.

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'

# Output from requesting moria1's descriptor from itself...
# % curl http://128.31.0.39:9131/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31

TEST_DESCRIPTOR = b"""\
router moria1 128.31.0.34 9101 0 9131
platform Tor 0.2.5.0-alpha-dev on Linux
protocols Link 1 2 Circuit 1
published 2013-07-05 23:48:52
fingerprint 9695 DFC3 5FFE B861 329B 9F1A B04C 4639 7020 CE31
uptime 1818933
bandwidth 512000 62914560 1307929
extra-info-digest 17D0142F6EBCDF60160EB1794FA6C9717D581F8C
caches-extra-info
onion-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALzd4bhz1usB7wpoaAvP+BBOnNIk7mByAKV6zvyQ0p1M09oEmxPMc3qD
AAm276oJNf0eq6KWC6YprzPWFsXEIdXSqA6RWXCII1JG/jOoy6nt478BkB8TS9I9
1MJW27ppRaqnLiTmBmM+qzrsgJGwf+onAgUKKH2GxlVgahqz8x6xAgMBAAE=
-----END RSA PUBLIC KEY-----
signing-key
-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBALtJ9uD7cD7iHjqNA3AgsX9prES5QN+yFQyr2uOkxzhvunnaf6SNhzWW
bkfylnMrRm/qCz/czcjZO6N6EKHcXmypehvP566B7gAQ9vDsb+l7VZVWgXvzNc2s
tl3P7qpC08rgyJh1GqmtQTCesIDqkEyWxwToympCt09ZQRq+fIttAgMBAAE=
-----END RSA PUBLIC KEY-----
hidden-service-dir
contact 1024D/28988BF5 arma mit edu
ntor-onion-key 9ZVjNkf/iLEnD685SpC5kcDytQ7u5ViiI9JOftdbE0k=
reject *:*
router-signature
-----BEGIN SIGNATURE-----
Y8Tj2e7mPbFJbguulkPEBVYzyO57p4btpWEXvRMD6vxIh/eyn25pehg5dUVBtZlL
iO3EUE0AEYah2W9gdz8t+i3Dtr0zgqLS841GC/TyDKCm+MKmN8d098qnwK0NGF9q
01NZPuSqXM1b6hnl2espFzL7XL8XEGRU+aeg+f/ukw4=
-----END SIGNATURE-----
"""


class TestDescriptorDownloader(unittest.TestCase):
  @patch(URL_OPEN)
  def test_query_download(self, urlopen_mock):
    """
    Check Query functionality when we successfully download a descriptor.
    """

    urlopen_mock.return_value = io.BytesIO(TEST_DESCRIPTOR)

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      validate = True,
    )

    expeced_url = 'http://128.31.0.39:9131/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31'
    self.assertEqual(expeced_url, query._pick_url())

    descriptors = list(query)
    self.assertEqual(1, len(descriptors))
    desc = descriptors[0]

    self.assertEqual('moria1', desc.nickname)
    self.assertEqual('128.31.0.34', desc.address)
    self.assertEqual('9695DFC35FFEB861329B9F1AB04C46397020CE31', desc.fingerprint)
    self.assertEqual(TEST_DESCRIPTOR.strip(), desc.get_bytes())

    urlopen_mock.assert_called_once_with(expeced_url, timeout = None)

  @patch(URL_OPEN)
  def test_query_with_malformed_content(self, urlopen_mock):
    """
    Query with malformed descriptor content.
    """

    descriptor_content = b'some malformed stuff'
    urlopen_mock.return_value = io.BytesIO(descriptor_content)

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      validate = True,
    )

    # checking via the iterator

    expected_error_msg = 'Content conform to being a server descriptor:\nsome malformed stuff'

    descriptors = list(query)
    self.assertEqual(0, len(descriptors))
    self.assertEqual(ValueError, type(query.error))
    self.assertEqual(expected_error_msg, str(query.error))

    # check via the run() method

    self.assertRaises(ValueError, query.run)

  @patch(URL_OPEN)
  def test_query_with_timeout(self, urlopen_mock):
    urlopen_mock.side_effect = socket.timeout('connection timed out')

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      fall_back_to_authority = False,
      timeout = 5,
      validate = True,
    )

    self.assertRaises(socket.timeout, query.run)
    urlopen_mock.assert_called_with(
      'http://128.31.0.39:9131/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      timeout = 5,
    )
    self.assertEqual(3, urlopen_mock.call_count)

  @patch(URL_OPEN)
  def test_can_iterate_multiple_times(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO(TEST_DESCRIPTOR)

    query = stem.descriptor.remote.Query(
      '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      validate = True,
    )

    # check that iterating over the query provides the descriptors each time

    self.assertEqual(1, len(list(query)))
    self.assertEqual(1, len(list(query)))
    self.assertEqual(1, len(list(query)))
