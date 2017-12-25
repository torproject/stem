"""
Integration tests for stem.descriptor.collector.
"""

import unittest

import test.require

from stem.descriptor.collector import CollecTor, Compression


class TestCollector(unittest.TestCase):
  @test.require.only_run_once
  @test.require.online
  def test_index_plaintext(self):
    self._test_index(Compression.NONE)

  @test.require.only_run_once
  @test.require.online
  def test_index_gzip(self):
    self._test_index(Compression.NONE)

  def _test_index(self, compression):
    collector = CollecTor(compression = compression)
    index = collector.index()

    self.assertEqual('https://collector.torproject.org', index['path'])
    self.assertEqual(['archive', 'recent'], [entry['path'] for entry in index['directories']])
