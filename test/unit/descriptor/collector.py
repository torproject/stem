"""
Unit tests for stem.descriptor.collector.
"""

import unittest

from stem.descriptor.collector import Compression, url


class TestCollector(unittest.TestCase):
  def test_url(self):
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index'))
    self.assertEqual('https://collector.torproject.org/index/index.json', url('index', compression = Compression.NONE))
    self.assertEqual('https://collector.torproject.org/index/index.json.gz', url('index', compression = Compression.GZ))
    self.assertEqual('https://collector.torproject.org/index/index.json.bz2', url('index', compression = Compression.BZ2))
    self.assertEqual('https://collector.torproject.org/index/index.json.xz', url('index', compression = Compression.XZ))
