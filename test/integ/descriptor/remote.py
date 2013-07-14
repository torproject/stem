"""
Integration tests for stem.descriptor.remote.
"""

import unittest

import stem.descriptor.remote
import test.runner

# Required to prevent unmarshal error when running this test alone.

import stem.descriptor.networkstatus

class TestDescriptorReader(unittest.TestCase):
  def test_using_authorities(self):
    """
    Fetches a descriptor from each of the directory authorities. This is
    intended to check that DIRECTORY_AUTHORITIES is still up to date (that
    addresses and ports haven't changed).

    This is hardcoded to fetch moria1's descriptor. If its fingerprint changes
    then this test will need to be updated.
    """

    if test.runner.require_online(self):
      return

    queries = []

    for authority, (address, dirport) in stem.descriptor.remote.DIRECTORY_AUTHORITIES.items():
      queries.append(stem.descriptor.remote.Query(
        address,
        dirport,
        '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
        'server-descriptor 1.0',
        30,
      ))

    for query in queries:
      try:
        descriptors = list(query.run())
      except Exception, exc:
        self.fail("Unable to use %s (%s:%s, %s): %s" % (authority, address, dirport, type(exc), exc))

      self.assertEqual(1, len(descriptors))
      self.assertEqual('moria1', descriptors[0].nickname)

