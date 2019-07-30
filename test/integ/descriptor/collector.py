"""
Integration tests for stem.descriptor.collector.
"""

import unittest

import test.require

from stem.descriptor import Compression
from stem.descriptor.collector import CollecTor


class TestCollector(unittest.TestCase):
  @test.require.only_run_once
  @test.require.online
  def test_index_plaintext(self):
    self._test_index(None)

  @test.require.only_run_once
  @test.require.online
  def test_index_gzip(self):
    self._test_index(Compression.GZIP)

  @test.require.only_run_once
  @test.require.online
  def test_index_bz2(self):
    self._test_index(Compression.BZ2)

  @test.require.only_run_once
  @test.require.online
  def test_index_lzma(self):
    self._test_index(Compression.LZMA)

  def _test_index(self, compression):
    if compression and not compression.available:
      self.skipTest('(%s unavailable)' % compression)

    collector = CollecTor()
    index = collector.index(compression = compression)

    self.assertEqual('https://collector.torproject.org', index['path'])
    self.assertEqual(['archive', 'contrib', 'recent'], [entry['path'] for entry in index['directories']])
