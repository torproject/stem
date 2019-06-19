"""
Unit tests for stem.descriptor.Compression.
"""

import unittest

from stem.descriptor import Compression

from test.unit.descriptor import get_resource


class TestCompression(unittest.TestCase):
  def test_decompress_plaintext(self):
    self._check_file(Compression.PLAINTEXT, 'compressed_identity')

  def test_decompress_gzip(self):
    self._check_file(Compression.GZIP, 'compressed_gzip')

  def test_decompress_bz2(self):
    self._check_file(Compression.BZ2, 'compressed_bz2')

  def test_decompress_lzma(self):
    self._check_file(Compression.LZMA, 'compressed_lzma')

  def test_decompress_zstd(self):
    self._check_file(Compression.ZSTD, 'compressed_zstd')

  def _check_file(self, compression, filename):
    """
    Decompress one of our 'compressed_*' server descriptors.
    """

    if not compression.available:
      self.skipTest('(%s unavailable)' % compression)
      return

    with open(get_resource(filename), 'rb') as compressed_file:
      content = compression.decompress(compressed_file.read())
      self.assertTrue(content.startswith(b'router moria1 128.31.0.34 9101 0 9131'))
