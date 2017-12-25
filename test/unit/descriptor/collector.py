"""
Unit tests for stem.descriptor.collector.
"""

import unittest

from stem.descriptor.collector import GZIP, BZ2, LZMA, url


class TestCollector(unittest.TestCase):
  def test_url(self):
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index'))
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index', compression = None))
    self.assertEqual('https://collector.torproject.org/index/index.json.gz', url('index', compression = GZIP))
    self.assertEqual('https://collector.torproject.org/index/index.json.bz2', url('index', compression = BZ2))
    self.assertEqual('https://collector.torproject.org/index/index.json.xz', url('index', compression = LZMA))
