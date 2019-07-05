"""
Unit tests for stem.descriptor.collector.
"""

import io
import unittest

import stem.prereq

from stem.descriptor import Compression
from stem.descriptor.collector import CollecTor, url

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'


class TestCollector(unittest.TestCase):
  def test_url(self):
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index'))
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index', compression = None))
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index', compression = Compression.PLAINTEXT))
    self.assertEqual('https://collector.torproject.org/index/index.json.gz', url('index', compression = Compression.GZIP))
    self.assertEqual('https://collector.torproject.org/index/index.json.bz2', url('index', compression = Compression.BZ2))
    self.assertEqual('https://collector.torproject.org/index/index.json.xz', url('index', compression = Compression.LZMA))

  @patch(URL_OPEN)
  def test_retries(self, urlopen_mock):
    collector = CollecTor(retries = 4)
    urlopen_mock.side_effect = IOError('boom')

    self.assertRaisesRegexp(IOError, 'boom', collector.index)
    self.assertEqual(5, urlopen_mock.call_count)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'{"index_created":"2017-12-25 21:06","build_revision":"56a303e","path":"https://collector.torproject.org"}')))
  def test_index(self):
    expected = {
      'index_created': '2017-12-25 21:06',
      'build_revision': '56a303e',
      'path': 'https://collector.torproject.org'
    }

    collector = CollecTor(compression = Compression.PLAINTEXT)
    self.assertEqual(expected, collector.index())

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'not json')))
  def test_index_malformed_json(self):
    collector = CollecTor(compression = Compression.PLAINTEXT)

    if stem.prereq.is_python_3():
      self.assertRaisesRegexp(ValueError, 'Expecting value: line 1 column 1', collector.index)
    else:
      self.assertRaisesRegexp(ValueError, 'No JSON object could be decoded', collector.index)

  def test_index_malformed_compression(self):
    for compression in (Compression.GZIP, Compression.BZ2, Compression.LZMA):
      with patch(URL_OPEN, Mock(return_value = io.BytesIO(b'not compressed'))):
        collector = CollecTor(compression = compression)
        self.assertRaisesRegexp(IOError, 'Unable to decompress %s response' % compression, collector.index)
