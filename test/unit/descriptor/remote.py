"""
Unit tests for stem.descriptor.remote.
"""

import io
import socket
import time
import unittest

import stem
import stem.descriptor
import stem.descriptor.remote
import stem.prereq
import stem.util.str_tools

from stem.descriptor.remote import Compression
from test.unit.descriptor import read_resource

try:
  from http.client import HTTPMessage  # python3
except ImportError:
  from httplib import HTTPMessage  # python2

try:
  # added in python 3.3
  from unittest.mock import patch, Mock, MagicMock
except ImportError:
  from mock import patch, Mock, MagicMock

# The urlopen() method is in a different location depending on if we're using
# python 2.x or 3.x. The 2to3 converter accounts for this in imports, but not
# mock annotations.

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'

TEST_RESOURCE = '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31'

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

HEADER = '\r\n'.join([
  'Date: Fri, 13 Apr 2018 16:35:50 GMT',
  'Content-Type: application/octet-stream',
  'X-Your-Address-Is: 97.103.17.56',
  'Pragma: no-cache',
  'Content-Encoding: %s',
])


def _orport_mock(data, encoding = 'identity', response_code_header = None):
  if response_code_header is None:
    response_code_header = b'HTTP/1.0 200 OK\r\n'

  data = response_code_header + stem.util.str_tools._to_bytes(HEADER % encoding) + b'\r\n\r\n' + data
  cells = []

  for hunk in [data[i:i + 50] for i in range(0, len(data), 50)]:
    cell = Mock()
    cell.data = hunk
    cells.append(cell)

  connect_mock = MagicMock()
  relay_mock = connect_mock().__enter__()
  circ_mock = relay_mock.create_circuit().__enter__()
  circ_mock.directory.return_value = data
  return connect_mock


def _dirport_mock(data, encoding = 'identity'):
  dirport_mock = Mock()
  dirport_mock().read.return_value = data

  if stem.prereq.is_python_3():
    headers = HTTPMessage()

    for line in HEADER.splitlines():
      key, value = line.split(': ', 1)
      headers.add_header(key, encoding if key == 'Content-Encoding' else value)

    dirport_mock().headers = headers
  else:
    dirport_mock().headers = HTTPMessage(io.BytesIO(HEADER % encoding))

  return dirport_mock


class TestDescriptorDownloader(unittest.TestCase):
  def tearDown(self):
    # prevent our mocks from impacting other tests
    stem.descriptor.remote.SINGLETON_DOWNLOADER = None

  @patch('stem.client.Relay.connect', _orport_mock(TEST_DESCRIPTOR))
  def test_using_orport(self):
    """
    Download a descriptor through the ORPort.
    """

    reply = stem.descriptor.remote.their_server_descriptor(
      endpoints = [stem.ORPort('12.34.56.78', 1100)],
      validate = True,
    )

    self.assertEqual(1, len(list(reply)))
    self.assertEqual('moria1', list(reply)[0].nickname)
    self.assertEqual(5, len(reply.reply_headers))

  def test_orport_response_code_headers(self):
    """
    When successful Tor provides a '200 OK' status, but we should accept other 2xx
    response codes, reason text, and recognize HTTP errors.
    """

    response_code_headers = (
      b'HTTP/1.0 200 OK\r\n',
      b'HTTP/1.0 205 OK\r\n',
      b'HTTP/1.0 200 This is also alright\r\n',
    )

    for header in response_code_headers:
      with patch('stem.client.Relay.connect', _orport_mock(TEST_DESCRIPTOR, response_code_header = header)):
        stem.descriptor.remote.their_server_descriptor(
          endpoints = [stem.ORPort('12.34.56.78', 1100)],
          validate = True,
        ).run()

    with patch('stem.client.Relay.connect', _orport_mock(TEST_DESCRIPTOR, response_code_header = b'HTTP/1.0 500 Kaboom\r\n')):
      request = stem.descriptor.remote.their_server_descriptor(
        endpoints = [stem.ORPort('12.34.56.78', 1100)],
        validate = True,
      )

      self.assertRaisesRegexp(stem.ProtocolError, "^Response should begin with HTTP success, but was 'HTTP/1.0 500 Kaboom'", request.run)

  @patch(URL_OPEN, _dirport_mock(TEST_DESCRIPTOR))
  def test_using_dirport(self):
    """
    Download a descriptor through the DirPort.
    """

    reply = stem.descriptor.remote.their_server_descriptor(
      endpoints = [stem.DirPort('12.34.56.78', 1100)],
      validate = True,
    )

    self.assertEqual(1, len(list(reply)))
    self.assertEqual('moria1', list(reply)[0].nickname)
    self.assertEqual(5, len(reply.reply_headers))

  def test_gzip_url_override(self):
    query = stem.descriptor.remote.Query(TEST_RESOURCE + '.z', compression = Compression.PLAINTEXT, start = False)
    self.assertEqual([stem.descriptor.Compression.GZIP], query.compression)
    self.assertEqual(TEST_RESOURCE, query.resource)

  def test_zstd_support_check(self):
    with patch('stem.prereq.is_zstd_available', Mock(return_value = True)):
      query = stem.descriptor.remote.Query(TEST_RESOURCE, compression = Compression.ZSTD, start = False)
      self.assertEqual([stem.descriptor.Compression.ZSTD], query.compression)

    with patch('stem.prereq.is_zstd_available', Mock(return_value = False)):
      query = stem.descriptor.remote.Query(TEST_RESOURCE, compression = Compression.ZSTD, start = False)
      self.assertEqual([stem.descriptor.Compression.PLAINTEXT], query.compression)

  def test_lzma_support_check(self):
    with patch('stem.prereq.is_lzma_available', Mock(return_value = True)):
      query = stem.descriptor.remote.Query(TEST_RESOURCE, compression = Compression.LZMA, start = False)
      self.assertEqual([stem.descriptor.Compression.LZMA], query.compression)

    with patch('stem.prereq.is_lzma_available', Mock(return_value = False)):
      query = stem.descriptor.remote.Query(TEST_RESOURCE, compression = Compression.LZMA, start = False)
      self.assertEqual([stem.descriptor.Compression.PLAINTEXT], query.compression)

  @patch(URL_OPEN, _dirport_mock(read_resource('compressed_identity'), encoding = 'identity'))
  def test_compression_plaintext(self):
    """
    Download a plaintext descriptor.
    """

    descriptors = list(stem.descriptor.remote.get_server_descriptors(
      '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      compression = Compression.PLAINTEXT,
      validate = True,
    ))

    self.assertEqual(1, len(descriptors))
    self.assertEqual('moria1', descriptors[0].nickname)

  @patch(URL_OPEN, _dirport_mock(read_resource('compressed_gzip'), encoding = 'gzip'))
  def test_compression_gzip(self):
    """
    Download a gip compressed descriptor.
    """

    descriptors = list(stem.descriptor.remote.get_server_descriptors(
      '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      compression = Compression.GZIP,
      validate = True,
    ))

    self.assertEqual(1, len(descriptors))
    self.assertEqual('moria1', descriptors[0].nickname)

  @patch(URL_OPEN, _dirport_mock(read_resource('compressed_zstd'), encoding = 'x-zstd'))
  def test_compression_zstd(self):
    """
    Download a zstd compressed descriptor.
    """

    if not stem.prereq.is_zstd_available():
      self.skipTest('(requires zstd module)')
      return

    descriptors = list(stem.descriptor.remote.get_server_descriptors(
      '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      compression = Compression.ZSTD,
      validate = True,
    ))

    self.assertEqual(1, len(descriptors))
    self.assertEqual('moria1', descriptors[0].nickname)

  @patch(URL_OPEN, _dirport_mock(read_resource('compressed_lzma'), encoding = 'x-tor-lzma'))
  def test_compression_lzma(self):
    """
    Download a lzma compressed descriptor.
    """

    if not stem.prereq.is_lzma_available():
      self.skipTest('(requires lzma module)')
      return

    descriptors = list(stem.descriptor.remote.get_server_descriptors(
      '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      compression = Compression.LZMA,
      validate = True,
    ))

    self.assertEqual(1, len(descriptors))
    self.assertEqual('moria1', descriptors[0].nickname)

  @patch(URL_OPEN)
  def test_each_getter(self, dirport_mock):
    """
    Surface level exercising of each getter method for downloading descriptors.
    """

    downloader = stem.descriptor.remote.get_instance()

    downloader.get_server_descriptors()
    downloader.get_extrainfo_descriptors()
    downloader.get_microdescriptors('test-hash')
    downloader.get_consensus()
    downloader.get_vote(stem.directory.Authority.from_cache()['moria1'])
    downloader.get_key_certificates()
    downloader.get_bandwidth_file()
    downloader.get_detached_signatures()

  @patch(URL_OPEN, _dirport_mock(TEST_DESCRIPTOR))
  def test_reply_headers(self):
    query = stem.descriptor.remote.get_server_descriptors('9695DFC35FFEB861329B9F1AB04C46397020CE31', start = False)
    self.assertEqual(None, query.reply_headers)  # initially we don't have a reply
    query.run()

    self.assertEqual('Fri, 13 Apr 2018 16:35:50 GMT', query.reply_headers.get('date'))
    self.assertEqual('application/octet-stream', query.reply_headers.get('content-type'))
    self.assertEqual('97.103.17.56', query.reply_headers.get('x-your-address-is'))
    self.assertEqual('no-cache', query.reply_headers.get('pragma'))
    self.assertEqual('identity', query.reply_headers.get('content-encoding'))

    # getting headers should be case insensitive
    self.assertEqual('identity', query.reply_headers.get('CoNtEnT-ENCODING'))

    # request a header that isn't present
    self.assertEqual(None, query.reply_headers.get('no-such-header'))
    self.assertEqual('default', query.reply_headers.get('no-such-header', 'default'))

    descriptors = list(query)
    self.assertEqual(1, len(descriptors))
    self.assertEqual('moria1', descriptors[0].nickname)

  @patch(URL_OPEN, _dirport_mock(TEST_DESCRIPTOR))
  def test_query_download(self):
    """
    Check Query functionality when we successfully download a descriptor.
    """

    query = stem.descriptor.remote.Query(
      TEST_RESOURCE,
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      compression = Compression.PLAINTEXT,
      validate = True,
    )

    self.assertEqual(stem.DirPort('128.31.0.39', 9131), query._pick_endpoint())

    descriptors = list(query)
    self.assertEqual(1, len(descriptors))
    desc = descriptors[0]

    self.assertEqual('moria1', desc.nickname)
    self.assertEqual('128.31.0.34', desc.address)
    self.assertEqual('9695DFC35FFEB861329B9F1AB04C46397020CE31', desc.fingerprint)
    self.assertEqual(TEST_DESCRIPTOR, desc.get_bytes())

  @patch(URL_OPEN, _dirport_mock(b'some malformed stuff'))
  def test_query_with_malformed_content(self):
    """
    Query with malformed descriptor content.
    """

    query = stem.descriptor.remote.Query(
      TEST_RESOURCE,
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      compression = Compression.PLAINTEXT,
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
  def test_query_with_timeout(self, dirport_mock):
    def urlopen_call(*args, **kwargs):
      time.sleep(0.06)
      raise socket.timeout('connection timed out')

    dirport_mock.side_effect = urlopen_call

    query = stem.descriptor.remote.Query(
      TEST_RESOURCE,
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      fall_back_to_authority = False,
      timeout = 0.1,
      validate = True,
    )

    # After two requests we'll have reached our total permissable timeout.
    # It would be nice to check that we don't make a third, but this
    # assertion has proved unreliable so only checking for the exception.

    self.assertRaises(stem.DownloadTimeout, query.run)

  def test_query_with_invalid_endpoints(self):
    invalid_endpoints = {
      'hello': "'h' is a str.",
      ('hello',): "'hello' is a str.",
      (15,): "'15' is a int.",
      (('12.34.56.78', 15, 'third arg'),): "'('12.34.56.78', 15, 'third arg')' is a tuple.",
    }

    for endpoints, error_suffix in invalid_endpoints.items():
      expected_error = 'Endpoints must be an stem.ORPort, stem.DirPort, or two value tuple. ' + error_suffix
      self.assertRaisesWith(ValueError, expected_error, stem.descriptor.remote.Query, TEST_RESOURCE, 'server-descriptor 1.0', endpoints = endpoints)

  @patch(URL_OPEN, _dirport_mock(TEST_DESCRIPTOR))
  def test_can_iterate_multiple_times(self):
    query = stem.descriptor.remote.Query(
      TEST_RESOURCE,
      'server-descriptor 1.0',
      endpoints = [('128.31.0.39', 9131)],
      compression = Compression.PLAINTEXT,
      validate = True,
    )

    # check that iterating over the query provides the descriptors each time

    self.assertEqual(1, len(list(query)))
    self.assertEqual(1, len(list(query)))
    self.assertEqual(1, len(list(query)))
