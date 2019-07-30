"""
Unit tests for stem.descriptor.collector.
"""

import datetime
import io
import unittest

import stem.prereq

from stem.descriptor import Compression
from stem.descriptor.collector import CollecTor, File
from test.unit.descriptor import get_resource
from test.unit.descriptor.data.collector_index import EXAMPLE_INDEX

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'


with open(get_resource('collector_index.json'), 'rb') as index_file:
  EXAMPLE_INDEX_JSON = index_file.read()


class TestCollector(unittest.TestCase):
  # tests for the File class

  def test_file_guess_descriptor_types(self):
    test_values = {
      'archive/bridge-descriptors/extra-infos/bridge-extra-infos-2008-05.tar.xz': ('bridge-extra-info 1.3',),
      'archive/relay-descriptors/microdescs/microdescs-2014-01.tar.xz': ('network-status-microdesc-consensus-3 1.0', 'microdescriptor 1.0'),
      'archive/webstats/webstats-2015-03.tar': (),
      'archive/no_such_file.tar': (),
    }

    for path, expected in test_values.items():
      self.assertEqual(expected, File._guess_descriptor_types(path))

  def test_file_guess_compression(self):
    test_values = {
      'archive/relay-descriptors/microdescs/microdescs-2014-01.tar.xz': Compression.LZMA,
      'archive/webstats/webstats-2015-03.tar': Compression.PLAINTEXT,
      'recent/relay-descriptors/extra-infos/2019-07-03-02-05-00-extra-infos': Compression.PLAINTEXT,
    }

    for path, expected in test_values.items():
      self.assertEqual(expected, File._guess_compression(path))

  def test_file_guess_time_range(self):
    test_values = {
      'archive/relay-descriptors/microdescs/microdescs-2014-01.tar.xz':
        (datetime.datetime(2014, 1, 1), datetime.datetime(2014, 2, 1)),
      'recent/relay-descriptors/extra-infos/2019-07-03-02-05-00-extra-infos':
        (datetime.datetime(2019, 7, 3, 2, 5, 0), datetime.datetime(2019, 7, 3, 3, 5, 0)),
      'archive/relay-descriptors/certs.tar.xz':
        (None, None),
      'archive/relay-descriptors/microdescs/microdescs-2014-12.tar.xz':
        (datetime.datetime(2014, 12, 1), datetime.datetime(2015, 1, 1)),
      'recent/relay-descriptors/extra-infos/2019-07-03-23-05-00-extra-infos':
        (datetime.datetime(2019, 7, 3, 23, 5, 0), datetime.datetime(2019, 7, 4, 0, 5, 0))
    }

    for path, (expected_start, expected_end) in test_values.items():
      f = File(path, 7515396, '2014-02-07 03:59')
      self.assertEqual(expected_start, f.start)
      self.assertEqual(expected_end, f.end)

  # tests for the CollecTor class

  @patch(URL_OPEN)
  def test_index_plaintext(self, urlopen_mock):
    urlopen_mock.return_value = io.BytesIO(EXAMPLE_INDEX_JSON)

    collector = CollecTor()
    self.assertEqual(EXAMPLE_INDEX, collector.index(Compression.PLAINTEXT))
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json', timeout = None)

  @patch(URL_OPEN)
  def test_index_gzip(self, urlopen_mock):
    if not Compression.GZIP.available:
      self.skipTest('(gzip compression unavailable)')
      return

    import zlib
    urlopen_mock.return_value = io.BytesIO(zlib.compress(EXAMPLE_INDEX_JSON))

    collector = CollecTor()
    self.assertEqual(EXAMPLE_INDEX, collector.index(Compression.GZIP))
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json.gz', timeout = None)

  @patch(URL_OPEN)
  def test_index_bz2(self, urlopen_mock):
    if not Compression.BZ2.available:
      self.skipTest('(bz2 compression unavailable)')
      return

    import bz2
    urlopen_mock.return_value = io.BytesIO(bz2.compress(EXAMPLE_INDEX_JSON))

    collector = CollecTor()
    self.assertEqual(EXAMPLE_INDEX, collector.index(Compression.BZ2))
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json.bz2', timeout = None)

  @patch(URL_OPEN)
  def test_index_lzma(self, urlopen_mock):
    if not Compression.LZMA.available:
      self.skipTest('(lzma compression unavailable)')
      return

    import lzma
    urlopen_mock.return_value = io.BytesIO(lzma.compress(EXAMPLE_INDEX_JSON))

    collector = CollecTor()
    self.assertEqual(EXAMPLE_INDEX, collector.index(Compression.LZMA))
    urlopen_mock.assert_called_with('https://collector.torproject.org/index/index.json.xz', timeout = None)

  @patch(URL_OPEN)
  def test_index_retries(self, urlopen_mock):
    urlopen_mock.side_effect = IOError('boom')

    collector = CollecTor(retries = 0)
    self.assertRaisesRegexp(IOError, 'boom', collector.index)
    self.assertEqual(1, urlopen_mock.call_count)

    urlopen_mock.reset_mock()

    collector = CollecTor(retries = 4)
    self.assertRaisesRegexp(IOError, 'boom', collector.index)
    self.assertEqual(5, urlopen_mock.call_count)

  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'not json')))
  def test_index_malformed_json(self):
    collector = CollecTor()

    if stem.prereq.is_python_3():
      self.assertRaisesRegexp(ValueError, 'Expecting value: line 1 column 1', collector.index, Compression.PLAINTEXT)
    else:
      self.assertRaisesRegexp(ValueError, 'No JSON object could be decoded', collector.index, Compression.PLAINTEXT)

  def test_index_malformed_compression(self):
    for compression in (Compression.GZIP, Compression.BZ2, Compression.LZMA):
      if not compression.available:
        continue

      with patch(URL_OPEN, Mock(return_value = io.BytesIO(b'not compressed'))):
        collector = CollecTor()
        self.assertRaisesRegexp(IOError, 'Failed to decompress as %s' % compression, collector.index, compression)

  @patch('stem.descriptor.collector.CollecTor.index', Mock(return_value = EXAMPLE_INDEX))
  def test_files(self):
    collector = CollecTor()
    files = collector.files()
    self.assertEqual(85, len(files))

    extrainfo_file = list(filter(lambda x: x.path.endswith('extra-infos-2007-09.tar.xz'), files))[0]
    self.assertEqual('archive/relay-descriptors/extra-infos/extra-infos-2007-09.tar.xz', extrainfo_file.path)
    self.assertEqual(Compression.LZMA, extrainfo_file.compression)
    self.assertEqual(6459884, extrainfo_file.size)
    self.assertEqual(datetime.datetime(2016, 6, 23, 9, 54), extrainfo_file.last_modified)

  @patch('stem.descriptor.collector.CollecTor.index', Mock(return_value = EXAMPLE_INDEX))
  def test_files_by_descriptor_type(self):
    collector = CollecTor()

    self.assertEqual([
      'archive/relay-descriptors/server-descriptors/server-descriptors-2005-12.tar.xz',
      'archive/relay-descriptors/server-descriptors/server-descriptors-2006-02.tar.xz',
      'archive/relay-descriptors/server-descriptors/server-descriptors-2006-03.tar.xz',
      'recent/relay-descriptors/server-descriptors/2019-07-03-02-05-00-server-descriptors',
      'recent/relay-descriptors/server-descriptors/2019-07-03-03-05-00-server-descriptors',
      'recent/relay-descriptors/server-descriptors/2019-07-03-04-05-00-server-descriptors',
    ], [f.path for f in collector.files(descriptor_type = 'server-descriptor')])

  @patch('stem.descriptor.collector.CollecTor.index', Mock(return_value = EXAMPLE_INDEX))
  def test_file_by_date(self):
    collector = CollecTor()

    self.assertEqual([
      'recent/relay-descriptors/server-descriptors/2019-07-03-02-05-00-server-descriptors',
      'recent/relay-descriptors/server-descriptors/2019-07-03-03-05-00-server-descriptors',
      'recent/relay-descriptors/server-descriptors/2019-07-03-04-05-00-server-descriptors',
    ], [f.path for f in collector.files(descriptor_type = 'server-descriptor', start = datetime.datetime(2007, 1, 1))])

    self.assertEqual([
      'archive/relay-descriptors/server-descriptors/server-descriptors-2005-12.tar.xz',
      'archive/relay-descriptors/server-descriptors/server-descriptors-2006-02.tar.xz',
      'archive/relay-descriptors/server-descriptors/server-descriptors-2006-03.tar.xz',
    ], [f.path for f in collector.files(descriptor_type = 'server-descriptor', end = datetime.datetime(2007, 1, 1))])

    self.assertEqual([
      'archive/relay-descriptors/server-descriptors/server-descriptors-2006-03.tar.xz',
    ], [f.path for f in collector.files(descriptor_type = 'server-descriptor', start = datetime.datetime(2006, 2, 10), end = datetime.datetime(2007, 1, 1))])
