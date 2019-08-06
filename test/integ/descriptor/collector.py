"""
Integration tests for stem.descriptor.collector.
"""

import datetime
import unittest

import test.require

import stem.descriptor.collector

from stem.descriptor import Compression

RECENT = datetime.datetime.utcnow() - datetime.timedelta(minutes = 60)


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

  @test.require.only_run_once
  @test.require.online
  def test_downloading_server_descriptors(self):
    recent_descriptors = list(stem.descriptor.collector.get_server_descriptors(start = RECENT))

    if not (300 < len(recent_descriptors) < 800):
      self.fail('Downloaded %i descriptors, expected 300-800' % len(recent_descriptors))  # 584 on 8/5/19

  @test.require.only_run_once
  @test.require.online
  def test_downloading_extrainfo_descriptors(self):
    recent_descriptors = list(stem.descriptor.collector.get_extrainfo_descriptors(start = RECENT))

    if not (300 < len(recent_descriptors) < 800):
      self.fail('Downloaded %i descriptors, expected 300-800' % len(recent_descriptors))

  def _test_index(self, compression):
    if compression and not compression.available:
      self.skipTest('(%s unavailable)' % compression)
      return

    collector = stem.descriptor.collector.CollecTor()
    index = collector.index(compression = compression)

    self.assertEqual('https://collector.torproject.org', index['path'])
    self.assertEqual(['archive', 'contrib', 'recent'], [entry['path'] for entry in index['directories']])
