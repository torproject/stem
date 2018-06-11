"""
Integration tests for stem.descriptor.remote.
"""

import unittest

import stem
import stem.descriptor
import stem.descriptor.extrainfo_descriptor
import stem.descriptor.networkstatus
import stem.descriptor.remote
import stem.descriptor.router_status_entry
import stem.descriptor.server_descriptor
import stem.directory
import test.require


class TestDescriptorDownloader(unittest.TestCase):
  @test.require.only_run_once
  @test.require.online
  @test.require.cryptography
  def test_downloading_via_orport(self):
    moria1 = stem.directory.Authority.from_cache()['moria1']

    desc = list(stem.descriptor.remote.their_server_descriptor(
      endpoints = [stem.ORPort(moria1.address, moria1.or_port)],
      fall_back_to_authority = False,
    ).run())[0]

    self.assertEqual('moria1', desc.nickname)
    self.assertTrue(isinstance(desc, stem.descriptor.server_descriptor.ServerDescriptor))

  @test.require.only_run_once
  @test.require.online
  def test_downloading_via_dirport(self):
    moria1 = stem.directory.Authority.from_cache()['moria1']

    desc = list(stem.descriptor.remote.their_server_descriptor(
      endpoints = [stem.DirPort(moria1.address, moria1.dir_port)],
      fall_back_to_authority = False,
    ).run())[0]

    self.assertEqual('moria1', desc.nickname)
    self.assertTrue(isinstance(desc, stem.descriptor.server_descriptor.ServerDescriptor))

  @test.require.only_run_once
  @test.require.online
  def test_shorthand_aliases(self):
    """
    Quick sanity test that we can call our shorthand aliases for getting
    descriptors.
    """

    desc = list(stem.descriptor.remote.get_server_descriptors('9695DFC35FFEB861329B9F1AB04C46397020CE31').run())[0]
    self.assertEqual('moria1', desc.nickname)

    desc = list(stem.descriptor.remote.get_extrainfo_descriptors('9695DFC35FFEB861329B9F1AB04C46397020CE31').run())[0]
    self.assertEqual('moria1', desc.nickname)

    consensus = list(stem.descriptor.remote.get_consensus())
    self.assertTrue(len(consensus) > 50)

  @test.require.only_run_once
  @test.require.online
  def test_authorities_are_up_to_date(self):
    """
    Check that our hardcoded directory authority data matches the present
    consensus.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader()
    consensus = downloader.get_consensus(document_handler = stem.descriptor.DocumentHandler.BARE_DOCUMENT).run()[0]

    for auth in consensus.directory_authorities:
      if auth.nickname == 'dannenberg-legacy':
        continue  # skip due to https://trac.torproject.org/projects/tor/ticket/17906

      stem_auth = stem.directory.Authority.from_cache().get(auth.nickname)

      if not stem_auth:
        self.fail("%s isn't a recognized directory authority in stem" % auth.nickname)

      for attr in ('v3ident', 'or_port', 'dir_port'):
        if auth.nickname == 'moria1' and attr == 'address':
          continue  # skip due to https://trac.torproject.org/projects/tor/ticket/14955

        if getattr(auth, attr) != getattr(stem_auth, attr):
          self.fail('%s has %s %s, but we expected %s' % (auth.nickname, attr, getattr(auth, attr), getattr(stem_auth, attr)))

  @test.require.only_run_once
  @test.require.online
  def test_using_authorities(self):
    """
    Fetches a descriptor from each of the directory authorities. This is
    intended to check that DIRECTORY_AUTHORITIES is still up to date (that
    addresses and ports haven't changed).

    This is hardcoded to fetch moria1's descriptor. If its fingerprint changes
    then this test will need to be updated.
    """

    queries = []

    for nickname, authority in stem.directory.Authority.from_cache().items():
      queries.append((stem.descriptor.remote.Query(
        '/tor/server/fp/9695DFC35FFEB861329B9F1AB04C46397020CE31',
        'server-descriptor 1.0',
        endpoints = [(authority.address, authority.dir_port)],
        timeout = 30,
        validate = True,
      ), authority))

    for query, authority in queries:
      try:
        descriptors = list(query.run())
      except Exception as exc:
        self.fail('Unable to use %s (%s:%s, %s): %s' % (authority.nickname, authority.address, authority.dir_port, type(exc), exc))

      self.assertEqual(1, len(descriptors))
      self.assertEqual('moria1', descriptors[0].nickname)

  @test.require.only_run_once
  @test.require.online
  def test_use_directory_mirrors(self):
    """
    Checks that we can fetch and use a list of directory mirrors.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader()
    downloader.use_directory_mirrors()
    self.assertTrue(len(downloader._endpoints) > 50)

  @test.require.only_run_once
  @test.require.online
  def test_get_server_descriptors(self):
    """
    Exercises the downloader's get_server_descriptors() method.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader(validate = True)

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
    self.assertTrue(isinstance(single_query_results[0], stem.descriptor.server_descriptor.ServerDescriptor))

    self.assertEqual(2, len(list(multiple_query)))

  @test.require.only_run_once
  @test.require.online
  def test_get_extrainfo_descriptors(self):
    """
    Exercises the downloader's get_extrainfo_descriptors() method.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader(validate = True)

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

  @test.require.only_run_once
  @test.require.online
  def test_get_consensus(self):
    """
    Exercises the downloader's get_consensus() method.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader(validate = True)

    consensus_query = downloader.get_consensus()
    consensus_query.run()

    consensus = list(consensus_query)
    self.assertTrue(len(consensus) > 50)
    self.assertTrue(isinstance(consensus[0], stem.descriptor.router_status_entry.RouterStatusEntryV3))

  @test.require.only_run_once
  @test.require.online
  def test_get_microdescriptor_consensus(self):
    """
    Exercises the downloader's get_consensus() method for fetching a
    microdescriptor consensus.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader(validate = True)

    consensus_query = downloader.get_consensus(microdescriptor = True)
    consensus_query.run()

    consensus = list(consensus_query)
    self.assertTrue(len(consensus) > 50)
    self.assertTrue(isinstance(consensus[0], stem.descriptor.router_status_entry.RouterStatusEntryMicroV3))

  @test.require.only_run_once
  @test.require.online
  def test_get_key_certificates(self):
    """
    Exercises the downloader's get_key_certificates() method.
    """

    downloader = stem.descriptor.remote.DescriptorDownloader(validate = True)

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
