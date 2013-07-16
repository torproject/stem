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
        '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
        'server-descriptor 1.0',
        endpoints = [(address, dirport)],
        timeout = 30,
      ))

    for query in queries:
      try:
        descriptors = list(query.run())
      except Exception, exc:
        self.fail("Unable to use %s (%s:%s, %s): %s" % (authority, address, dirport, type(exc), exc))

      self.assertEqual(1, len(descriptors))
      self.assertEqual('moria1', descriptors[0].nickname)

  def test_get_server_descriptors(self):
    """
    Exercises the downloader's get_server_descriptors() method.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader()

    # Fetch a single descriptor and a batch. I'd love to also exercise
    # retrieving all descriptors, but that adds roughly a minute to the runtime
    # of this test and adds an appreciable load to directory authorities.

    single_query = downloader.get_server_descriptors('9695DFC35FFEB861329B9F1AB04C46397020CE31')

    multiple_query = downloader.get_server_descriptors([
      '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      '847B1F850344D7876491A54892F904934E4EB85D',
    ])

    # Explicitly running the queries so they'll provide a useful error if
    # unsuccessful.

    single_query.run()
    multiple_query.run()

    single_query_results = list(single_query)
    self.assertEqual(1, len(single_query_results))
    self.assertEqual('moria1', single_query_results[0].nickname)

    self.assertEqual(2, len(list(multiple_query)))

