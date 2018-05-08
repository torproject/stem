"""
Integration tests for stem.directory.Authority.
"""

import unittest

import stem.directory
import test.require


class TestAuthority(unittest.TestCase):
  @test.require.online
  def test_cache_is_up_to_date(self):
    """
    Check if the cached authorities we bundle are up to date.
    """

    self.assertEqual(stem.directory.Authority.from_cache(), stem.directory.Authority.from_remote())
