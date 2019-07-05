"""
Unit tests for stem.descriptor.collector.
"""

import io
import unittest

import stem.prereq

from stem.descriptor import Compression
from stem.descriptor.collector import CollecTor

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'

MINIMAL_INDEX = {
  'index_created': '2017-12-25 21:06',
  'build_revision': '56a303e',
  'path': 'https://collector.torproject.org'
}

MINIMAL_INDEX_JSON = b'{"index_created":"2017-12-25 21:06","build_revision":"56a303e","path":"https://collector.torproject.org"}'


class TestCollector(unittest.TestCase):
  @patch(URL_OPEN)
  def test_download_plaintext(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO(MINIMAL_INDEX_JSON)

    collector = CollecTor(compression = Compression.PLAINTEXT)
    self.assertEqual(MINIMAL_INDEX, collector.index())
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json', timeout = None)

  @patch(URL_OPEN)
  def test_download_gzip(self, urlopen_mock):
    if not Compression.GZIP.available:
      self.skipTest('(gzip compression unavailable)')
      return

    import zlib
    urlopen_mock.return_value = io.BytesIO(zlib.compress(MINIMAL_INDEX_JSON))

    collector = CollecTor(compression = Compression.GZIP)
    self.assertEqual(MINIMAL_INDEX, collector.index())
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json.gz', timeout = None)

  @patch(URL_OPEN)
  def test_download_bz2(self, urlopen_mock):
    if not Compression.BZ2.available:
      self.skipTest('(bz2 compression unavailable)')
      return

    import bz2
    urlopen_mock.return_value = io.BytesIO(bz2.compress(MINIMAL_INDEX_JSON))

    collector = CollecTor(compression = Compression.BZ2)
    self.assertEqual(MINIMAL_INDEX, collector.index())
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json.bz2', timeout = None)

  @patch(URL_OPEN)
  def test_download_lzma(self, urlopen_mock):
    if not Compression.LZMA.available:
      self.skipTest('(lzma compression unavailable)')
      return

    import lzma
    urlopen_mock.return_value = io.BytesIO(lzma.compress(MINIMAL_INDEX_JSON))

    collector = CollecTor(compression = Compression.LZMA)
    self.assertEqual(MINIMAL_INDEX, collector.index())
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json.lzma', timeout = None)

  @patch(URL_OPEN)
  def test_download_retries(self, urlopen_mock):
    urlopen_mock.side_effect = IOError('boom')

    collector = CollecTor(retries = 0)
    self.assertRaisesRegexp(IOError, 'boom', collector.index)
    self.assertEqual(1, urlopen_mock.call_count)

    urlopen_mock.reset_mock()

    collector = CollecTor(retries = 4)
    self.assertRaisesRegexp(IOError, 'boom', collector.index)
    self.assertEqual(5, urlopen_mock.call_count)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(MINIMAL_INDEX_JSON)))
  def test_index(self):
    collector = CollecTor(compression = Compression.PLAINTEXT)
    self.assertEqual(MINIMAL_INDEX, collector.index())

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'not json')))
  def test_index_malformed_json(self):
    collector = CollecTor(compression = Compression.PLAINTEXT)

    if stem.prereq.is_python_3():
      self.assertRaisesRegexp(ValueError, 'Expecting value: line 1 column 1', collector.index)
    else:
      self.assertRaisesRegexp(ValueError, 'No JSON object could be decoded', collector.index)

  def test_index_malformed_compression(self):
    for compression in (Compression.GZIP, Compression.BZ2, Compression.LZMA):
      if not compression.available:
        next

      with patch(URL_OPEN, Mock(return_value = io.BytesIO(b'not compressed'))):
        collector = CollecTor(compression = compression)
        self.assertRaisesRegexp(IOError, 'Unable to decompress %s response' % compression, collector.index)
