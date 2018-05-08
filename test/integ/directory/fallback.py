"""
Integration tests for stem.directory.Fallback.
"""

import unittest

import stem.descriptor.remote
import stem.directory
import test.require


class TestFallback(unittest.TestCase):
  @test.require.online
  def test_cache_is_up_to_date(self):
    """
    Check if the cached fallbacks we bundle are up to date.
    """

    cached_fallback_directories = stem.directory.Fallback.from_cache()
    latest_fallback_directories = stem.directory.Fallback.from_remote()

    if cached_fallback_directories != latest_fallback_directories:
      self.fail("Stem's cached fallback directories are out of date. Please run 'cache_fallback_directories.py'...\n\n%s" % stem.directory._fallback_directory_differences(cached_fallback_directories, latest_fallback_directories))

  @test.require.online
  def test_fallback_directory_reachability(self):
    """
    Fetch information from each fallback directory to confirm that it's
    available.
    """

    # Don't run this test by default. Once upon a time it was fine, but tor has
    # added so many fallbacks now that this takes a looong time. :(

    self.skipTest('(skipped by default)')
    return

    unsuccessful = {}
    downloader = stem.descriptor.remote.DescriptorDownloader()
    moria1_v3ident = stem.directory.Authority.from_cache()['moria1'].v3ident

    for fallback_directory in stem.directory.Fallback.from_cache().values():
      try:
        downloader.get_key_certificates(authority_v3idents = moria1_v3ident, endpoints = [(fallback_directory.address, fallback_directory.dir_port)]).run()
      except Exception as exc:
        unsuccessful[fallback_directory] = exc

    if unsuccessful:
      lines = ['We were unable to contact the following fallback directories...\n']

      for fallback_directory, exc in unsuccessful.items():
        lines.append('* %s:%s (%s): %s' % (fallback_directory.address, fallback_directory.dir_port, fallback_directory.fingerprint, exc))

      self.fail('\n'.join(lines))
