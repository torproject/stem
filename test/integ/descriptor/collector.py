"""
Integration tests for stem.descriptor.collector.
"""

import unittest

import test.require

from stem.descriptor.collector import CollecTor, Compression


class TestCollector(unittest.TestCase):
  @test.require.only_run_once
  @test.require.online
  def test_index(self):
    collector = CollecTor(compression = Compression.NONE)
    index = collector.index()

    self.assertEqual('https://collector.torproject.org', index['path'])
    self.assertEqual(['archive', 'recent'], [entry['path'] for entry in index['directories']])
