"""
Integration tests for stem.descriptor.remote.
"""

import unittest

import stem.descriptor.extrainfo_descriptor
import stem.descriptor.microdescriptor
import stem.descriptor.networkstatus
import stem.descriptor.remote
import stem.descriptor.router_status_entry
import stem.descriptor.server_descriptor
import test.runner


class TestDescriptorDownloader(unittest.TestCase):
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
    elif test.runner.only_run_once(self, 'test_using_authorities'):
      return

    queries = []

    for nickname, authority in stem.descriptor.remote.get_authorities().items():
      queries.append((stem.descriptor.remote.Query(
        '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
        'server-descriptor 1.0',
        endpoints = [(authority.address, authority.dir_port)],
        timeout = 30,
      ), authority))

    for query, authority in queries:
      try:
        descriptors = list(query.run())
      except Exception as exc:
        self.fail('Unable to use %s (%s:%s, %s): %s' % (authority.nickname, authority.address, authority.dir_port, type(exc), exc))

      self.assertEqual(1, len(descriptors))
      self.assertEqual('moria1', descriptors[0].nickname)

  def test_use_directory_mirrors(self):
    """
    Checks that we can fetch and use a list of directory mirrors.
    """

    if test.runner.require_online(self):
      return
    elif test.runner.only_run_once(self, 'test_use_directory_mirrors'):
      return

    downloader = stem.descriptor.remote.DescriptorDownloader()
    downloader.use_directory_mirrors()
    self.assertTrue(len(downloader._endpoints) > 50)

  def test_get_server_descriptors(self):
    """
    Exercises the downloader's get_server_descriptors() method.
    """

    if test.runner.require_online(self):
      return
    elif test.runner.only_run_once(self, 'test_get_server_descriptors'):
      return

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
    self.assertTrue(isinstance(single_query_results[0], stem.descriptor.stem.descriptor.server_descriptor.ServerDescriptor))

    self.assertEqual(2, len(list(multiple_query)))

  def test_get_extrainfo_descriptors(self):
    """
    Exercises the downloader's get_extrainfo_descriptors() method.
    """

    if test.runner.require_online(self):
      return
    elif test.runner.only_run_once(self, 'test_get_extrainfo_descriptors'):
      return

    downloader = stem.descriptor.remote.DescriptorDownloader()

    single_query = downloader.get_extrainfo_descriptors('9695DFC35FFEB861329B9F1AB04C46397020CE31')

    multiple_query = downloader.get_extrainfo_descriptors([
      '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      '847B1F850344D7876491A54892F904934E4EB85D',
    ])

    single_query.run()
    multiple_query.run()

    single_query_results = list(single_query)
    self.assertEqual(1, len(single_query_results))
    self.assertEqual('moria1', single_query_results[0].nickname)
    self.assertTrue(isinstance(single_query_results[0], stem.descriptor.extrainfo_descriptor.ExtraInfoDescriptor))

    self.assertEqual(2, len(list(multiple_query)))

  def test_get_microdescriptors(self):
    """
    Exercises the downloader's get_microdescriptors() method.
    """

    # TODO: method needs to be fixed - not quite sure what's going wrong...

    test.runner.skip(self, '(test presently broken)')
    return

    if test.runner.require_online(self):
      return
    elif test.runner.only_run_once(self, 'test_get_microdescriptors'):
      return

    downloader = stem.descriptor.remote.DescriptorDownloader()

    single_query = downloader.get_microdescriptors('6dCl6ab8CLo0LeMjxi/MZgVJiZgWN8WKTesWPBMtyTo')

    multiple_query = downloader.get_microdescriptors([
      '6dCl6ab8CLo0LeMjxi/MZgVJiZgWN8WKTesWPBMtyTo',  # moria1
      'oXBV80OwMACBJpqNeZrYSXF18l9EJCi4/mB8UOl9sME',  # tor26
    ])

    single_query.run()
    multiple_query.run()

    single_query_results = list(single_query)
    self.assertEqual(1, len(single_query_results))
    self.assertEqual('moria1', single_query_results[0].digest)
    self.assertTrue(isinstance(single_query_results[0], stem.descriptor.microdescriptor.Microdescriptor))

    self.assertEqual(2, len(list(multiple_query)))

  def test_get_consensus(self):
    """
    Exercises the downloader's get_consensus() method.
    """

    if test.runner.require_online(self):
      return
    elif test.runner.only_run_once(self, 'test_get_consensus'):
      return

    downloader = stem.descriptor.remote.DescriptorDownloader()

    consensus_query = downloader.get_consensus()
    consensus_query.run()

    consensus = list(consensus_query)
    self.assertTrue(len(consensus) > 50)
    self.assertTrue(isinstance(consensus[0], stem.descriptor.router_status_entry.RouterStatusEntryV3))

  def test_get_key_certificates(self):
    """
    Exercises the downloader's get_key_certificates() method.
    """

    if test.runner.require_online(self):
      return
    elif test.runner.only_run_once(self, 'test_get_key_certificates'):
      return

    downloader = stem.descriptor.remote.DescriptorDownloader()

    single_query = downloader.get_key_certificates('D586D18309DED4CD6D57C18FDB97EFA96D330566')

    multiple_query = downloader.get_key_certificates([
      'D586D18309DED4CD6D57C18FDB97EFA96D330566',
      '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
    ])

    single_query.run()
    multiple_query.run()

    single_query_results = list(single_query)
    self.assertEqual(1, len(single_query_results))
    self.assertEqual('D586D18309DED4CD6D57C18FDB97EFA96D330566', single_query_results[0].fingerprint)
    self.assertTrue(isinstance(single_query_results[0], stem.descriptor.networkstatus.KeyCertificate))

    self.assertEqual(2, len(list(multiple_query)))
