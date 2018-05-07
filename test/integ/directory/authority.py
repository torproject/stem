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

    cached_authorities = stem.directory.Authority.from_cache()
    latest_authorities = stem.directory.Authority.from_remote()

    for nickname in cached_authorities:
      if nickname not in latest_authorities:
        self.fail('%s is no longer a directory authority in tor' % nickname)

    for nickname in latest_authorities:
      if nickname not in cached_authorities:
        self.fail('%s is now a directory authority in tor' % nickname)

    # tor doesn't note if an autority is a bwauth or not, so we need to exclude
    # that from our comparison

    for attr in ('address', 'or_port', 'dir_port', 'fingerprint', 'nickname', 'v3ident'):
      for auth in cached_authorities.values():
        cached_value = getattr(auth, attr)
        latest_value = getattr(latest_authorities[auth.nickname], attr)

        if cached_value != latest_value:
          self.fail('The %s of the %s authority is %s in tor but %s in stem' % (attr, auth.nickname, latest_value, cached_value))
