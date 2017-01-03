"""
Unit tests for the NetworkStatusDocumentV3 of stem.descriptor.networkstatus.
"""

import datetime
import io
import unittest

import stem.descriptor
import stem.version

from stem import Flag
from stem.util import str_type

from stem.descriptor.networkstatus import (
  HEADER_STATUS_DOCUMENT_FIELDS,
  FOOTER_STATUS_DOCUMENT_FIELDS,
  DEFAULT_PARAMS,
  PackageVersion,
  DirectoryAuthority,
  NetworkStatusDocumentV3,
  _parse_file,
)

from stem.descriptor.router_status_entry import (
  RouterStatusEntryV3,
  RouterStatusEntryMicroV3,
)

from test.mocking import (
  get_router_status_entry_v3,
  get_router_status_entry_micro_v3,
  get_directory_authority,
  get_network_status_document_v3,
  DOC_SIG,
  NETWORK_STATUS_DOCUMENT_FOOTER,
)

from test.unit.descriptor import get_resource

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

BANDWIDTH_WEIGHT_ENTRIES = (
  'Wbd', 'Wbe', 'Wbg', 'Wbm',
  'Wdb',
  'Web', 'Wed', 'Wee', 'Weg', 'Wem',
  'Wgb', 'Wgd', 'Wgg', 'Wgm',
  'Wmb', 'Wmd', 'Wme', 'Wmg', 'Wmm',
)


class TestNetworkStatusDocument(unittest.TestCase):
  def test_metrics_consensus(self):
    """
    Checks if consensus documents from Metrics are parsed properly.
    """

    consensus_path = get_resource('metrics_consensus')

    for specify_type in (True, False):
      with open(consensus_path, 'rb') as descriptor_file:
        if specify_type:
          descriptors = stem.descriptor.parse_file(descriptor_file, 'network-status-consensus-3 1.0')
        else:
          descriptors = stem.descriptor.parse_file(descriptor_file)

        router = next(descriptors)
        self.assertEqual('sumkledi', router.nickname)
        self.assertEqual('0013D22389CD50D0B784A3E4061CB31E8CE8CEB5', router.fingerprint)
        self.assertEqual('F260ABF1297B445E04354E236F4159140FF7768F', router.digest)
        self.assertEqual(datetime.datetime(2012, 7, 12, 4, 1, 55), router.published)
        self.assertEqual('178.218.213.229', router.address)
        self.assertEqual(80, router.or_port)
        self.assertEqual(None, router.dir_port)

  def test_consensus_v3(self):
    """
    Checks that version 3 consensus documents are properly parsed.
    """

    # the document's expected client and server versions are the same
    expected_versions = [stem.version.Version(v) for v in (
      '0.2.2.35',
      '0.2.2.36',
      '0.2.2.37',
      '0.2.3.10-alpha',
      '0.2.3.11-alpha',
      '0.2.3.12-alpha',
      '0.2.3.13-alpha',
      '0.2.3.14-alpha',
      '0.2.3.15-alpha',
      '0.2.3.16-alpha',
      '0.2.3.17-beta',
      '0.2.3.18-rc',
      '0.2.3.19-rc',
    )]

    expected_flags = set(
      ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir',
       'Named', 'Running', 'Stable', 'Unnamed', 'V2Dir', 'Valid'])

    expected_bandwidth_weights = {
      'Wbd': 3335, 'Wbe': 0, 'Wbg': 3536, 'Wbm': 10000, 'Wdb': 10000,
      'Web': 10000, 'Wed': 3329, 'Wee': 10000, 'Weg': 3329, 'Wem': 10000,
      'Wgb': 10000, 'Wgd': 3335, 'Wgg': 6464, 'Wgm': 6464, 'Wmb': 10000,
      'Wmd': 3335, 'Wme': 0, 'Wmg': 3536, 'Wmm': 10000
    }

    expected_signature = """-----BEGIN SIGNATURE-----
HFXB4497LzESysYJ/4jJY83E5vLjhv+igIxD9LU6lf6ftkGeF+lNmIAIEKaMts8H
mfWcW0b+jsrXcJoCxV5IrwCDF3u1aC3diwZY6yiG186pwWbOwE41188XI2DeYPwE
I/TJmV928na7RLZe2mGHCAW3VQOvV+QkCfj05VZ8CsY=
-----END SIGNATURE-----"""

    with open(get_resource('cached-consensus'), 'rb') as descriptor_file:
      document = stem.descriptor.networkstatus.NetworkStatusDocumentV3(descriptor_file.read(), default_params = False)

      self.assertEqual(3, document.version)
      self.assertEqual(None, document.version_flavor)
      self.assertEqual(True, document.is_consensus)
      self.assertEqual(False, document.is_vote)
      self.assertEqual(False, document.is_microdescriptor)
      self.assertEqual(datetime.datetime(2012, 7, 12, 10, 0, 0), document.valid_after)
      self.assertEqual(datetime.datetime(2012, 7, 12, 11, 0, 0), document.fresh_until)
      self.assertEqual(datetime.datetime(2012, 7, 12, 13, 0, 0), document.valid_until)
      self.assertEqual(300, document.vote_delay)
      self.assertEqual(300, document.dist_delay)
      self.assertEqual(expected_versions, document.client_versions)
      self.assertEqual(expected_versions, document.server_versions)
      self.assertEqual(expected_flags, set(document.known_flags))
      self.assertEqual([], document.packages)
      self.assertEqual({'CircuitPriorityHalflifeMsec': 30000, 'bwauthpid': 1}, document.params)

      self.assertEqual(12, document.consensus_method)
      self.assertEqual(expected_bandwidth_weights, document.bandwidth_weights)
      self.assertEqual([], document.consensus_methods)
      self.assertEqual(None, document.published)
      self.assertEqual([], document.get_unrecognized_lines())

      router = document.routers['0013D22389CD50D0B784A3E4061CB31E8CE8CEB5']
      self.assertEqual('sumkledi', router.nickname)
      self.assertEqual('0013D22389CD50D0B784A3E4061CB31E8CE8CEB5', router.fingerprint)
      self.assertEqual('F260ABF1297B445E04354E236F4159140FF7768F', router.digest)
      self.assertEqual(datetime.datetime(2012, 7, 12, 4, 1, 55), router.published)
      self.assertEqual('178.218.213.229', router.address)
      self.assertEqual(80, router.or_port)
      self.assertEqual(None, router.dir_port)
      self.assertEqual(set(['Exit', 'Fast', 'Named', 'Running', 'Valid']), set(router.flags))

      authority = document.directory_authorities[0]
      self.assertEqual(8, len(document.directory_authorities))
      self.assertEqual('tor26', authority.nickname)
      self.assertEqual('14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4', authority.fingerprint)
      self.assertEqual('86.59.21.38', authority.hostname)
      self.assertEqual('86.59.21.38', authority.address)
      self.assertEqual(80, authority.dir_port)
      self.assertEqual(443, authority.or_port)
      self.assertEqual('Peter Palfrader', authority.contact)
      self.assertEqual('0B6D1E9A300B895AA2D0B427F92917B6995C3C1C', authority.vote_digest)
      self.assertEqual(None, authority.legacy_dir_key)
      self.assertEqual(None, authority.key_certificate)

      signature = document.signatures[0]
      self.assertEqual(8, len(document.signatures))
      self.assertEqual('sha1', signature.method)
      self.assertEqual('14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4', signature.identity)
      self.assertEqual('BF112F1C6D5543CFD0A32215ACABD4197B5279AD', signature.key_digest)
      self.assertEqual(expected_signature, signature.signature)

  def test_metrics_vote(self):
    """
    Checks if vote documents from Metrics are parsed properly.
    """

    vote_path = get_resource('metrics_vote')

    with open(vote_path, 'rb') as descriptor_file:
      descriptors = stem.descriptor.parse_file(descriptor_file)

      router = next(descriptors)
      self.assertEqual('sumkledi', router.nickname)
      self.assertEqual('0013D22389CD50D0B784A3E4061CB31E8CE8CEB5', router.fingerprint)
      self.assertEqual('0799F806200B005F01E40A9A7F1A21C988AE8FB1', router.digest)
      self.assertEqual(datetime.datetime(2012, 7, 11, 4, 22, 53), router.published)
      self.assertEqual('178.218.213.229', router.address)
      self.assertEqual(80, router.or_port)
      self.assertEqual(None, router.dir_port)

  def test_vote(self):
    """
    Checks that vote documents are properly parsed.
    """

    expected_flags = set(
      ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir',
       'Running', 'Stable', 'V2Dir', 'Valid'])

    expected_identity_key = """-----BEGIN RSA PUBLIC KEY-----
MIIBigKCAYEA6uSmsoxj2MiJ3qyZq0qYXlRoG8o82SNqg+22m+t1c7MlQOZWPJYn
XeMcBCt8xrTeIt2ZI+Q/Kt2QJSeD9WZRevTKk/kn5Tg2+xXPogalUU47y5tUohGz
+Q8+CxtRSXpDxBHL2P8rLHvGrI69wbNHGoQkce/7gJy9vw5Ie2qzbyXk1NG6V8Fb
pr6A885vHo6TbhUnolz2Wqt/kN+UorjLkN2H3fV+iGcQFv42SyHYGDLa0WwL3PJJ
r/veu36S3VaHBrfhutfioi+d3d4Ya0bKwiWi5Lm2CHuuRTgMpHLU9vlci8Hunuxq
HsULe2oMsr4VEic7sW5SPC5Obpx6hStHdNv1GxoSEm3/vIuPM8pINpU5ZYAyH9yO
Ef22ZHeiVMMKmpV9TtFyiFqvlI6GpQn3mNbsQqF1y3XCA3Q4vlRAkpgJVUSvTxFP
2bNDobOyVCpCM/rwxU1+RCNY5MFJ/+oktUY+0ydvTen3gFdZdgNqCYjKPLfBNm9m
RGL7jZunMUNvAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_signing_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJ5itcJRYNEM3Qf1OVWLRkwjqf84oXPc2ZusaJ5zOe7TVvBMra9GNyc0
NM9y6zVkHCAePAjr4KbW/8P1olA6FUE2LV9bozaU1jFf6K8B2OELKs5FUEW+n+ic
GM0x6MhngyXonWOcKt5Gj+mAu5lrno9tpNbPkz2Utr/Pi0nsDhWlAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_key_crosscert = """-----BEGIN ID SIGNATURE-----
RHYImGTwg36wmEdAn7qaRg2sAfql7ZCtPIL/O3lU5OIdXXp0tNn/K00Bamqohjk+
Tz4FKsKXGDlbGv67PQcZPOK6NF0GRkNh4pk89prrDO4XwtEn7rkHHdBH6/qQ7IRG
GdDZHtZ1a69oFZvPWD3hUaB50xeIe7GoKdKIfdNNJ+8=
-----END ID SIGNATURE-----"""

    expected_key_certification = """-----BEGIN SIGNATURE-----
fasWOGyUZ3iMCYpDfJ+0JcMiTH25sXPWzvlHorEOyOMbaMqRYpZU4GHzt1jLgdl6
AAoR6KdamsLg5VE8xzst48a4UFuzHFlklZ5O8om2rcvDd5DhSnWWYZnYJecqB+bo
dNisPmaIVSAWb29U8BpNRj4GMC9KAgGYUj8aE/KtutAeEekFfFEHTfWZ2fFp4j3m
9rY8FWraqyiF+Emq1T8pAAgMQ+79R3oZxq0TXS42Z4Anhms735ccauKhI3pDKjbl
tD5vAzIHOyjAOXj7a6jY/GrnaBNuJ4qe/4Hf9UmzK/jKKwG95BPJtPTT4LoFwEB0
KG2OUeQUNoCck4nDpsZwFqPlrWCHcHfTV2iDYFV1HQWDTtZz/qf+GtB8NXsq+I1w
brADmvReM2BD6p/13h0QURCI5hq7ZYlIKcKrBa0jn1d9cduULl7vgKsRCJDls/ID
emBZ6pUxMpBmV0v+PrA3v9w4DlE7GHAq61FF/zju2kpqj6MInbEvI/E+e438sWsL
-----END SIGNATURE-----"""

    expected_signature = """-----BEGIN SIGNATURE-----
fskXN84wB3mXfo+yKGSt0AcDaaPuU3NwMR3ROxWgLN0KjAaVi2eV9PkPCsQkcgw3
JZ/1HL9sHyZfo6bwaC6YSM9PNiiY6L7rnGpS7UkHiFI+M96VCMorvjm5YPs3FioJ
DnN5aFtYKiTc19qIC7Nmo+afPdDEf0MlJvEOP5EWl3w=
-----END SIGNATURE-----"""

    with open(get_resource('vote'), 'rb') as descriptor_file:
      document = stem.descriptor.networkstatus.NetworkStatusDocumentV3(descriptor_file.read(), default_params = False)

      self.assertEqual(3, document.version)
      self.assertEqual(None, document.version_flavor)
      self.assertEqual(False, document.is_consensus)
      self.assertEqual(True, document.is_vote)
      self.assertEqual(False, document.is_microdescriptor)
      self.assertEqual(datetime.datetime(2012, 7, 12, 0, 0, 0), document.valid_after)
      self.assertEqual(datetime.datetime(2012, 7, 12, 1, 0, 0), document.fresh_until)
      self.assertEqual(datetime.datetime(2012, 7, 12, 3, 0, 0), document.valid_until)
      self.assertEqual(300, document.vote_delay)
      self.assertEqual(300, document.dist_delay)
      self.assertEqual([], document.client_versions)
      self.assertEqual([], document.server_versions)
      self.assertEqual(expected_flags, set(document.known_flags))
      self.assertEqual([], document.packages)
      self.assertEqual({'CircuitPriorityHalflifeMsec': 30000, 'bwauthpid': 1}, document.params)

      self.assertEqual(None, document.consensus_method)
      self.assertEqual({}, document.bandwidth_weights)
      self.assertEqual(list(range(1, 13)), document.consensus_methods)
      self.assertEqual(datetime.datetime(2012, 7, 11, 23, 50, 1), document.published)
      self.assertEqual([], document.get_unrecognized_lines())

      router = document.routers['0013D22389CD50D0B784A3E4061CB31E8CE8CEB5']
      self.assertEqual('sumkledi', router.nickname)
      self.assertEqual('0013D22389CD50D0B784A3E4061CB31E8CE8CEB5', router.fingerprint)
      self.assertEqual('0799F806200B005F01E40A9A7F1A21C988AE8FB1', router.digest)
      self.assertEqual(datetime.datetime(2012, 7, 11, 4, 22, 53), router.published)
      self.assertEqual('178.218.213.229', router.address)
      self.assertEqual(80, router.or_port)
      self.assertEqual(None, router.dir_port)

      authority = document.directory_authorities[0]
      self.assertEqual(1, len(document.directory_authorities))
      self.assertEqual('turtles', authority.nickname)
      self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', authority.fingerprint)
      self.assertEqual('76.73.17.194', authority.hostname)
      self.assertEqual('76.73.17.194', authority.address)
      self.assertEqual(9030, authority.dir_port)
      self.assertEqual(9090, authority.or_port)
      self.assertEqual('Mike Perry <email>', authority.contact)
      self.assertEqual(None, authority.vote_digest)
      self.assertEqual(None, authority.legacy_dir_key)

      certificate = authority.key_certificate
      self.assertEqual(3, certificate.version)
      self.assertEqual(None, certificate.address)
      self.assertEqual(None, certificate.dir_port)
      self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', certificate.fingerprint)
      self.assertEqual(expected_identity_key, certificate.identity_key)
      self.assertEqual(datetime.datetime(2011, 11, 28, 21, 51, 4), certificate.published)
      self.assertEqual(datetime.datetime(2012, 11, 28, 21, 51, 4), certificate.expires)
      self.assertEqual(expected_signing_key, certificate.signing_key)
      self.assertEqual(expected_key_crosscert, certificate.crosscert)
      self.assertEqual(expected_key_certification, certificate.certification)

      signature = document.signatures[0]
      self.assertEqual(1, len(document.signatures))
      self.assertEqual('sha1', signature.method)
      self.assertEqual('27B6B5996C426270A5C95488AA5BCEB6BCC86956', signature.identity)
      self.assertEqual('D5C30C15BB3F1DA27669C2D88439939E8F418FCF', signature.key_digest)
      self.assertEqual(expected_signature, signature.signature)

  def test_minimal_consensus(self):
    """
    Parses a minimal network status document.
    """

    document = get_network_status_document_v3()

    expected_known_flags = [
      Flag.AUTHORITY, Flag.BADEXIT, Flag.EXIT,
      Flag.FAST, Flag.GUARD, Flag.HSDIR, Flag.NAMED, Flag.RUNNING,
      Flag.STABLE, Flag.UNNAMED, Flag.V2DIR, Flag.VALID]

    self.assertEqual({}, document.routers)
    self.assertEqual(3, document.version)
    self.assertEqual(None, document.version_flavor)
    self.assertEqual(True, document.is_consensus)
    self.assertEqual(False, document.is_vote)
    self.assertEqual(False, document.is_microdescriptor)
    self.assertEqual(9, document.consensus_method)
    self.assertEqual([], document.consensus_methods)
    self.assertEqual(None, document.published)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_after)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.fresh_until)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_until)
    self.assertEqual(300, document.vote_delay)
    self.assertEqual(300, document.dist_delay)
    self.assertEqual([], document.client_versions)
    self.assertEqual([], document.server_versions)
    self.assertEqual(expected_known_flags, document.known_flags)
    self.assertEqual([], document.packages)
    self.assertEqual({}, document.flag_thresholds)
    self.assertEqual(False, document.is_shared_randomness_participate)
    self.assertEqual([], document.shared_randomness_commitments)
    self.assertEqual(None, document.shared_randomness_previous_reveal_count)
    self.assertEqual(None, document.shared_randomness_previous_value)
    self.assertEqual(None, document.shared_randomness_current_reveal_count)
    self.assertEqual(None, document.shared_randomness_current_value)
    self.assertEqual(DEFAULT_PARAMS, document.params)
    self.assertEqual((), document.directory_authorities)
    self.assertEqual({}, document.bandwidth_weights)
    self.assertEqual([DOC_SIG], document.signatures)
    self.assertEqual([], document.get_unrecognized_lines())

  def test_minimal_vote(self):
    """
    Parses a minimal network status document.
    """

    document = get_network_status_document_v3({'vote-status': 'vote'})

    expected_known_flags = [
      Flag.AUTHORITY, Flag.BADEXIT, Flag.EXIT,
      Flag.FAST, Flag.GUARD, Flag.HSDIR, Flag.NAMED, Flag.RUNNING,
      Flag.STABLE, Flag.UNNAMED, Flag.V2DIR, Flag.VALID]

    self.assertEqual({}, document.routers)
    self.assertEqual(3, document.version)
    self.assertEqual(False, document.is_consensus)
    self.assertEqual(True, document.is_vote)
    self.assertEqual(None, document.consensus_method)
    self.assertEqual([1, 9], document.consensus_methods)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.published)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_after)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.fresh_until)
    self.assertEqual(datetime.datetime(2012, 9, 2, 22, 0, 0), document.valid_until)
    self.assertEqual(300, document.vote_delay)
    self.assertEqual(300, document.dist_delay)
    self.assertEqual([], document.client_versions)
    self.assertEqual([], document.server_versions)
    self.assertEqual(expected_known_flags, document.known_flags)
    self.assertEqual([], document.packages)
    self.assertEqual({}, document.flag_thresholds)
    self.assertEqual(False, document.is_shared_randomness_participate)
    self.assertEqual([], document.shared_randomness_commitments)
    self.assertEqual(None, document.shared_randomness_previous_reveal_count)
    self.assertEqual(None, document.shared_randomness_previous_value)
    self.assertEqual(None, document.shared_randomness_current_reveal_count)
    self.assertEqual(None, document.shared_randomness_current_value)
    self.assertEqual(DEFAULT_PARAMS, document.params)
    self.assertEqual({}, document.bandwidth_weights)
    self.assertEqual([DOC_SIG], document.signatures)
    self.assertEqual([], document.get_unrecognized_lines())

  def test_examples(self):
    """
    Run something similar to the examples in the header pydocs.
    """

    # makes a consensus with a couple routers, both with the same nickname

    entry1 = get_router_status_entry_v3({'s': 'Fast'})
    entry2 = get_router_status_entry_v3({'s': 'Valid'})
    content = get_network_status_document_v3(routers = (entry1, entry2), content = True)

    # first example: parsing via the NetworkStatusDocumentV3 constructor

    consensus_file = io.BytesIO(content)
    consensus = NetworkStatusDocumentV3(consensus_file.read())
    consensus_file.close()

    for router in consensus.routers.values():
      self.assertEqual('caerSidi', router.nickname)

    # second example: using stem.descriptor.parse_file

    with io.BytesIO(content) as consensus_file:
      for router in stem.descriptor.parse_file(consensus_file, 'network-status-consensus-3 1.0'):
        self.assertEqual('caerSidi', router.nickname)

  def test_handlers(self):
    """
    Try parsing a document with DocumentHandler.DOCUMENT and
    DocumentHandler.BARE_DOCUMENT.
    """

    # Simple sanity check that they provide the right type, and that the
    # document includes or excludes the router status entries as appropriate.

    entry1 = get_router_status_entry_v3({'s': 'Fast'})
    entry2 = get_router_status_entry_v3({
      'r': 'Nightfae AWt0XNId/OU2xX5xs5hVtDc5Mes 6873oEfM7fFIbxYtwllw9GPDwkA 2013-02-20 11:12:27 85.177.66.233 9001 9030',
      's': 'Valid',
    })

    content = get_network_status_document_v3(routers = (entry1, entry2), content = True)

    descriptors = list(stem.descriptor.parse_file(io.BytesIO(content), 'network-status-consensus-3 1.0', document_handler = stem.descriptor.DocumentHandler.DOCUMENT))
    self.assertEqual(1, len(descriptors))
    self.assertTrue(isinstance(descriptors[0], NetworkStatusDocumentV3))
    self.assertEqual(2, len(descriptors[0].routers))

    descriptors = list(stem.descriptor.parse_file(io.BytesIO(content), 'network-status-consensus-3 1.0', document_handler = stem.descriptor.DocumentHandler.BARE_DOCUMENT))
    self.assertEqual(1, len(descriptors))
    self.assertTrue(isinstance(descriptors[0], NetworkStatusDocumentV3))
    self.assertEqual(0, len(descriptors[0].routers))

  def test_parse_file(self):
    """
    Try parsing a document via the _parse_file() function.
    """

    entry1 = get_router_status_entry_v3({'s': 'Fast'})
    entry2 = get_router_status_entry_v3({'s': 'Valid'})
    content = get_network_status_document_v3(routers = (entry1, entry2), content = True)

    # the document that the entries refer to should actually be the minimal
    # descriptor (ie, without the entries)

    expected_document = get_network_status_document_v3()

    descriptor_file = io.BytesIO(content)
    entries = list(_parse_file(descriptor_file))

    self.assertEqual(entry1, entries[0])
    self.assertEqual(entry2, entries[1])
    self.assertEqual(expected_document, entries[0].document)

  def test_missing_fields(self):
    """
    Excludes mandatory fields from both a vote and consensus document.
    """

    for is_consensus in (True, False):
      attr = {'vote-status': 'consensus'} if is_consensus else {'vote-status': 'vote'}
      is_vote = not is_consensus

      for entries in (HEADER_STATUS_DOCUMENT_FIELDS, FOOTER_STATUS_DOCUMENT_FIELDS):
        for field, in_votes, in_consensus, is_mandatory in entries:
          if is_mandatory and field != 'vote-status' and ((is_consensus and in_consensus) or (is_vote and in_votes)):
            content = get_network_status_document_v3(attr, exclude = (field,), content = True)
            self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
            NetworkStatusDocumentV3(content, False)  # constructs without validation

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the document.
    """

    document = get_network_status_document_v3({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], document.get_unrecognized_lines())

  def test_duplicate_fields(self):
    """
    Almost all fields can only appear once. Checking that duplicates cause
    validation errors.
    """

    for is_consensus in (True, False):
      attr = {'vote-status': 'consensus'} if is_consensus else {'vote-status': 'vote'}
      lines = get_network_status_document_v3(attr, content = True).split(b'\n')

      for index, line in enumerate(lines):
        if not is_consensus and lines[index].startswith(b'dir-source'):
          break

        # Stop when we hit the 'directory-signature' for a couple reasons...
        # - that is the one field that can validly appear multiple times
        # - after it is a crypto blob, which won't trigger this kind of
        #   validation failure

        test_lines = list(lines)
        if line.startswith(b'directory-signature '):
          break

        # duplicates the line
        test_lines.insert(index, line)

        content = b'\n'.join(test_lines)
        self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
        NetworkStatusDocumentV3(content, False)  # constructs without validation

  def test_version(self):
    """
    Parses the network-status-version field, including trying to handle a
    different document version with the v3 parser.
    """

    document = get_network_status_document_v3({'network-status-version': '3'})
    self.assertEqual(3, document.version)
    self.assertEqual(None, document.version_flavor)
    self.assertEqual(False, document.is_microdescriptor)

    document = get_network_status_document_v3({'network-status-version': '3 microdesc'})
    self.assertEqual(3, document.version)
    self.assertEqual('microdesc', document.version_flavor)
    self.assertEqual(True, document.is_microdescriptor)

    content = get_network_status_document_v3({'network-status-version': '4'}, content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual(4, document.version)
    self.assertEqual(None, document.version_flavor)
    self.assertEqual(False, document.is_microdescriptor)

  def test_vote_status(self):
    """
    Parses the vote-status field.
    """

    document = get_network_status_document_v3({'vote-status': 'vote'})
    self.assertEqual(False, document.is_consensus)
    self.assertEqual(True, document.is_vote)

    content = get_network_status_document_v3({'vote-status': 'consensus'}, content = True)
    document = NetworkStatusDocumentV3(content)
    self.assertEqual(True, document.is_consensus)
    self.assertEqual(False, document.is_vote)

    test_values = (
      '',
      '   ',
      'votee',
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'vote-status': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual(True, document.is_consensus)
      self.assertEqual(False, document.is_vote)

  def test_consensus_methods(self):
    """
    Parses the consensus-methods field.
    """

    document = get_network_status_document_v3({'vote-status': 'vote', 'consensus-methods': '12 3 1 780'})
    self.assertEqual([12, 3, 1, 780], document.consensus_methods)

    # check that we default to including consensus-method 1
    content = get_network_status_document_v3({'vote-status': 'vote'}, ('consensus-methods',), content = True)
    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([1], document.consensus_methods)
    self.assertEqual(None, document.consensus_method)

    test_values = (
      (''),
      ('   '),
      ('1 2 3 a 5'),
      ('1 2 3 4.0 5'),
      ('2 3 4'),  # spec says version one must be included
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'vote-status': 'vote', 'consensus-methods': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      expected_value = [2, 3, 4] if test_value == '2 3 4' else [1]

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual(expected_value, document.consensus_methods)

  def test_consensus_method(self):
    """
    Parses the consensus-method field.
    """

    document = get_network_status_document_v3({'consensus-method': '12'})
    self.assertEqual(12, document.consensus_method)

    # check that we default to being consensus-method 1
    content = get_network_status_document_v3(exclude = ('consensus-method',), content = True)
    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual(1, document.consensus_method)
    self.assertEqual([], document.consensus_methods)

    test_values = (
      '',
      '   ',
      'a',
      '1 2',
      '2.0',
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'consensus-method': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual(1, document.consensus_method)

  def test_time_fields(self):
    """
    Parses invalid published, valid-after, fresh-until, and valid-until fields.
    All are simply datetime values.
    """

    expected = datetime.datetime(2012, 9, 2, 22, 0, 0)
    test_value = '2012-09-02 22:00:00'

    document = get_network_status_document_v3({
      'vote-status': 'vote',
      'published': test_value,
      'valid-after': test_value,
      'fresh-until': test_value,
      'valid-until': test_value,
    })

    self.assertEqual(expected, document.published)
    self.assertEqual(expected, document.valid_after)
    self.assertEqual(expected, document.fresh_until)
    self.assertEqual(expected, document.valid_until)

    test_values = (
      '',
      '   ',
      '2012-12-12',
      '2012-12-12 01:01:',
      '2012-12-12 01:a1:01',
    )

    for field in ('published', 'valid-after', 'fresh-until', 'valid-until'):
      attr = field.replace('-', '_')

      for test_value in test_values:
        content = get_network_status_document_v3({'vote-status': 'vote', field: test_value}, content = True)
        self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

        document = NetworkStatusDocumentV3(content, False)
        self.assertEqual(None, getattr(document, attr))

  def test_voting_delay(self):
    """
    Parses the voting-delay field.
    """

    document = get_network_status_document_v3({'voting-delay': '12 345'})
    self.assertEqual(12, document.vote_delay)
    self.assertEqual(345, document.dist_delay)

    test_values = (
      '',
      '   ',
      '1 a',
      '1\t2',
      '1 2.0',
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'voting-delay': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual(None, document.vote_delay)
      self.assertEqual(None, document.dist_delay)

  def test_version_lists(self):
    """
    Parses client-versions and server-versions fields. Both are comma separated
    lists of tor versions.
    """

    expected = [stem.version.Version('1.2.3.4'), stem.version.Version('56.789.12.34-alpha')]
    test_value = '1.2.3.4,56.789.12.34-alpha'

    document = get_network_status_document_v3({'client-versions': test_value, 'server-versions': test_value})
    self.assertEqual(expected, document.client_versions)
    self.assertEqual(expected, document.server_versions)

    test_values = (
      (''),
      ('   '),
      ('1.2.3.4,'),
      ('1.2.3.4,1.2.3.a'),
    )

    for field in ('client-versions', 'server-versions'):
      attr = field.replace('-', '_')

      for test_value in test_values:
        content = get_network_status_document_v3({field: test_value}, content = True)
        self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

        document = NetworkStatusDocumentV3(content, False)
        self.assertEqual([], getattr(document, attr))

  def test_packages(self):
    """
    Parse the package line. These can appear multiple times, and have any
    number of digests.
    """

    test_values = (
      (['Stem 1.3.0 https://stem.torproject.org/'],
         [PackageVersion('Stem', '1.3.0', 'https://stem.torproject.org/', {})]),
      (['Stem 1.3.0 https://stem.torproject.org/ sha1=5d676c8124b4be1f52ddc8e15ca143cad211eeb4 md5=600ad5e2fc4caf585c1bdaaa532b7e82'],
         [PackageVersion('Stem', '1.3.0', 'https://stem.torproject.org/', {'sha1': '5d676c8124b4be1f52ddc8e15ca143cad211eeb4', 'md5': '600ad5e2fc4caf585c1bdaaa532b7e82'})]),
      (['Stem 1.3.0 https://stem.torproject.org/', 'Txtorcon 0.13.0 https://github.com/meejah/txtorcon'],
         [PackageVersion('Stem', '1.3.0', 'https://stem.torproject.org/', {}),
          PackageVersion('Txtorcon', '0.13.0', 'https://github.com/meejah/txtorcon', {})]),
    )

    for test_value, expected_value in test_values:
      document = get_network_status_document_v3({'package': '\npackage '.join(test_value)})
      self.assertEqual(expected_value, document.packages)

    test_values = (
      '',
      '    ',
      'Stem',
      'Stem 1.3.0',
      'Stem 1.3.0 https://stem.torproject.org/ keyword_field',
      'Stem 1.3.0 https://stem.torproject.org/ keyword_field key=value',
      'Stem 1.3.0 https://stem.torproject.org/ key=value keyword_field',
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'package': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual([], document.packages)

  def test_known_flags(self):
    """
    Parses some known-flag entries. Just exercising the field, there's not much
    to test here.
    """

    test_values = (
      ('', []),
      ('   ', []),
      ('BadExit', [Flag.BADEXIT]),
      ('BadExit ', [Flag.BADEXIT]),
      ('BadExit   ', [Flag.BADEXIT]),
      ('BadExit Fast', [Flag.BADEXIT, Flag.FAST]),
      ('BadExit Unrecognized Fast', [Flag.BADEXIT, 'Unrecognized', Flag.FAST]),
    )

    for test_value, expected_value in test_values:
      document = get_network_status_document_v3({'known-flags': test_value})
      self.assertEqual(expected_value, document.known_flags)

  def test_flag_thresholds(self):
    """
    Parses the flag-thresholds entry.
    """

    test_values = (
      ('', {}),
      ('fast-speed=40960', {str_type('fast-speed'): 40960}),    # numeric value
      ('guard-wfu=94.669%', {str_type('guard-wfu'): 0.94669}),  # percentage value
      ('guard-wfu=94.669% guard-tk=691200', {str_type('guard-wfu'): 0.94669, str_type('guard-tk'): 691200}),  # multiple values
    )

    for test_value, expected_value in test_values:
      document = get_network_status_document_v3({'vote-status': 'vote', 'flag-thresholds': test_value})
      self.assertEqual(expected_value, document.flag_thresholds)

    # parses a full entry found in an actual vote

    full_line = 'stable-uptime=693369 stable-mtbf=153249 fast-speed=40960 guard-wfu=94.669% guard-tk=691200 guard-bw-inc-exits=174080 guard-bw-exc-exits=184320 enough-mtbf=1'

    expected_value = {
      str_type('stable-uptime'): 693369,
      str_type('stable-mtbf'): 153249,
      str_type('fast-speed'): 40960,
      str_type('guard-wfu'): 0.94669,
      str_type('guard-tk'): 691200,
      str_type('guard-bw-inc-exits'): 174080,
      str_type('guard-bw-exc-exits'): 184320,
      str_type('enough-mtbf'): 1,
    }

    document = get_network_status_document_v3({'vote-status': 'vote', 'flag-thresholds': full_line})
    self.assertEqual(expected_value, document.flag_thresholds)

    test_values = (
      'stable-uptime 693369',   # not a key=value mapping
      'stable-uptime=a693369',  # non-numeric value
      'guard-wfu=94.669%%',     # double quote
      'stable-uptime=693369\tstable-mtbf=153249',  # non-space divider
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'vote-status': 'vote', 'flag-thresholds': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual({}, document.flag_thresholds)

  def test_shared_randomness(self):
    """
    Parses the shared randomness attributes.
    """

    COMMITMENT_1 = '1 sha3-256 4CAEC248004A0DC6CE86EBD5F608C9B05500C70C AAAAAFd4/kAaklgYr4ijHZjXXy/B354jQfL31BFhhE46nuOHSPITyw== AAAAAFd4/kCpZeis3yJyr//rz8hXCeeAhHa4k3lAcAiMJd1vEMTPuw=='
    COMMITMENT_2 = '1 sha3-256 598536A9DD4E6C0F18B4AD4B88C7875A0A29BA31 AAAAAFd4/kC7S920awC5/HF5RfX4fKZtYqjm6qMh9G91AcjZm13DQQ=='

    document = get_network_status_document_v3(OrderedDict([
      ('vote-status', 'vote'),
      ('shared-rand-participate', ''),
      ('shared-rand-commit', '%s\nshared-rand-commit %s' % (COMMITMENT_1, COMMITMENT_2)),
      ('shared-rand-previous-value', '8 hAQLxyt0U3gu7QR2owixRCbIltcyPrz3B0YBfUshOkE='),
      ('shared-rand-current-value', '7 KEIfSB7Db+ToasQIzJhbh0CtkeSePHLEehO+ams/RTU='),
    ]))

    self.assertEqual(True, document.is_shared_randomness_participate)
    self.assertEqual(8, document.shared_randomness_previous_reveal_count)
    self.assertEqual('hAQLxyt0U3gu7QR2owixRCbIltcyPrz3B0YBfUshOkE=', document.shared_randomness_previous_value)
    self.assertEqual(7, document.shared_randomness_current_reveal_count)
    self.assertEqual('KEIfSB7Db+ToasQIzJhbh0CtkeSePHLEehO+ams/RTU=', document.shared_randomness_current_value)

    self.assertEqual(2, len(document.shared_randomness_commitments))

    first_commitment = document.shared_randomness_commitments[0]
    self.assertEqual(1, first_commitment.version)
    self.assertEqual('sha3-256', first_commitment.algorithm)
    self.assertEqual('4CAEC248004A0DC6CE86EBD5F608C9B05500C70C', first_commitment.identity)
    self.assertEqual('AAAAAFd4/kAaklgYr4ijHZjXXy/B354jQfL31BFhhE46nuOHSPITyw==', first_commitment.commit)
    self.assertEqual('AAAAAFd4/kCpZeis3yJyr//rz8hXCeeAhHa4k3lAcAiMJd1vEMTPuw==', first_commitment.reveal)

    second_commitment = document.shared_randomness_commitments[1]
    self.assertEqual(1, second_commitment.version)
    self.assertEqual('sha3-256', second_commitment.algorithm)
    self.assertEqual('598536A9DD4E6C0F18B4AD4B88C7875A0A29BA31', second_commitment.identity)
    self.assertEqual('AAAAAFd4/kC7S920awC5/HF5RfX4fKZtYqjm6qMh9G91AcjZm13DQQ==', second_commitment.commit)
    self.assertEqual(None, second_commitment.reveal)

  def test_shared_randomness_malformed(self):
    """
    Checks shared randomness with malformed values.
    """

    test_values = [
      ({'vote-status': 'vote', 'shared-rand-commit': 'hi sha3-256 598536A9DD4E6C0F18B4AD4B88C7875A0A29BA31 AAAAAFd4/kC7S920awC5/HF5RfX4fKZtYqjm6qMh9G91AcjZm13DQQ=='},
        "The version on our 'shared-rand-commit' line wasn't an integer: hi sha3-256 598536A9DD4E6C0F18B4AD4B88C7875A0A29BA31 AAAAAFd4/kC7S920awC5/HF5RfX4fKZtYqjm6qMh9G91AcjZm13DQQ=="),
      ({'vote-status': 'vote', 'shared-rand-commit': 'sha3-256 598536A9DD4E6C0F18B4AD4B88C7875A0A29BA31 AAAAAFd4/kC7S920awC5/HF5RfX4fKZtYqjm6qMh9G91AcjZm13DQQ=='},
        "'shared-rand-commit' must at least have a 'Version AlgName Identity Commit': sha3-256 598536A9DD4E6C0F18B4AD4B88C7875A0A29BA31 AAAAAFd4/kC7S920awC5/HF5RfX4fKZtYqjm6qMh9G91AcjZm13DQQ=="),
      ({'vote-status': 'vote', 'shared-rand-current-value': 'hi KEIfSB7Db+ToasQIzJhbh0CtkeSePHLEehO+ams/RTU='},
        "A network status document's 'shared-rand-current-value' line must be a pair of values, the first an integer but was 'hi KEIfSB7Db+ToasQIzJhbh0CtkeSePHLEehO+ams/RTU='"),
      ({'vote-status': 'vote', 'shared-rand-current-value': 'KEIfSB7Db+ToasQIzJhbh0CtkeSePHLEehO+ams/RTU='},
        "A network status document's 'shared-rand-current-value' line must be a pair of values, the first an integer but was 'KEIfSB7Db+ToasQIzJhbh0CtkeSePHLEehO+ams/RTU='"),
    ]

    for attr, expected_exception in test_values:
      content = get_network_status_document_v3(attr, content = True)

      try:
        NetworkStatusDocumentV3(content, True)
        self.fail("validation should've rejected malformed shared randomness attribute")
      except ValueError as exc:
        self.assertEqual(expected_exception, str(exc))

      document = NetworkStatusDocumentV3(content, False)

      self.assertEqual([], document.shared_randomness_commitments)
      self.assertEqual(None, document.shared_randomness_previous_reveal_count)
      self.assertEqual(None, document.shared_randomness_previous_value)
      self.assertEqual(None, document.shared_randomness_current_reveal_count)
      self.assertEqual(None, document.shared_randomness_current_value)

  def test_params(self):
    """
    General testing for the 'params' line, exercising the happy cases.
    """

    document = get_network_status_document_v3({'params': 'CircuitPriorityHalflifeMsec=30000 bwauthpid=1 unrecognized=-122'})
    self.assertEqual(30000, document.params['CircuitPriorityHalflifeMsec'])
    self.assertEqual(1, document.params['bwauthpid'])
    self.assertEqual(-122, document.params['unrecognized'])

    # empty params line
    content = get_network_status_document_v3({'params': ''}, content = True)
    document = NetworkStatusDocumentV3(content, default_params = True)
    self.assertEqual(DEFAULT_PARAMS, document.params)

    content = get_network_status_document_v3({'params': ''}, content = True)
    document = NetworkStatusDocumentV3(content, default_params = False)
    self.assertEqual({}, document.params)

  def test_params_malformed(self):
    """
    Parses a 'params' line with malformed content.
    """

    test_values = (
      'foo=',
      'foo=abc',
      'foo=+123',
      'foo=12\tbar=12',
    )

    for test_value in test_values:
      content = get_network_status_document_v3({'params': test_value}, content = True)
      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual(DEFAULT_PARAMS, document.params)

  def test_params_range(self):
    """
    Check both the furthest valid 'params' values and values that are out of
    bounds.
    """

    test_values = (
      ('foo=2147483648', {'foo': 2147483648}, False),
      ('foo=-2147483649', {'foo': -2147483649}, False),
      ('foo=2147483647', {'foo': 2147483647}, True),
      ('foo=-2147483648', {'foo': -2147483648}, True),

      # param with special range constraints
      ('circwindow=99', {'circwindow': 99}, False),
      ('circwindow=1001', {'circwindow': 1001}, False),
      ('circwindow=500', {'circwindow': 500}, True),

      # param that relies on another param for its constraints
      ('cbtclosequantile=79 cbtquantile=80', {'cbtclosequantile': 79, 'cbtquantile': 80}, False),
      ('cbtclosequantile=80 cbtquantile=80', {'cbtclosequantile': 80, 'cbtquantile': 80}, True),
    )

    for test_value, expected_value, is_ok in test_values:
      content = get_network_status_document_v3({'params': test_value}, content = True)

      if is_ok:
        document = NetworkStatusDocumentV3(content, default_params = False)
      else:
        self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
        document = NetworkStatusDocumentV3(content, False, default_params = False)

      self.assertEqual(expected_value, document.params)

  def test_params_misordered(self):
    """
    Check that the 'params' line is rejected if out of order.
    """

    content = get_network_status_document_v3({'params': 'unrecognized=-122 bwauthpid=1'}, content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False, default_params = False)
    self.assertEqual({}, document.params)

  def test_footer_consensus_method_requirement(self):
    """
    Check that validation will notice if a footer appears before it was
    introduced.
    """

    content = get_network_status_document_v3({'consensus-method': '8'}, content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([DOC_SIG], document.signatures)
    self.assertEqual([], document.get_unrecognized_lines())

    # excludes a footer from a version that shouldn't have it

    document = get_network_status_document_v3({'consensus-method': '8'}, ('directory-footer', 'directory-signature'))
    self.assertEqual([], document.signatures)
    self.assertEqual([], document.get_unrecognized_lines())

    # Prior to conensus method 9 votes can still have a signature in their
    # footer...
    #
    # https://trac.torproject.org/7932

    document = get_network_status_document_v3(
      {
        'vote-status': 'vote',
        'consensus-methods': '1 8',
      },
      exclude = ('directory-footer',),
      authorities = (get_directory_authority(is_vote = True),)
    )

    self.assertEqual([DOC_SIG], document.signatures)
    self.assertEqual([], document.get_unrecognized_lines())

  def test_footer_with_value(self):
    """
    Tries to parse a descriptor with content on the 'directory-footer' line.
    """

    content = get_network_status_document_v3({'directory-footer': 'blarg'}, content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([DOC_SIG], document.signatures)
    self.assertEqual([], document.get_unrecognized_lines())

  def test_bandwidth_wights_ok(self):
    """
    Parses a properly formed 'bandwidth-wights' line. Negative bandwidth
    weights might or might not be valid. The spec doesn't say, so making sure
    that we accept them.
    """

    weight_entries, expected = [], {}

    for index, key in enumerate(BANDWIDTH_WEIGHT_ENTRIES):
      weight_entries.append('%s=%i' % (key, index - 5))
      expected[key] = index - 5

    document = get_network_status_document_v3({'bandwidth-weights': ' '.join(weight_entries)})
    self.assertEqual(expected, document.bandwidth_weights)

  def test_bandwidth_wights_malformed(self):
    """
    Provides malformed content in the 'bandwidth-wights' line.
    """

    test_values = (
      'Wbe',
      'Wbe=',
      'Wbe=a',
      'Wbe=+7',
    )

    base_weight_entry = ' '.join(['%s=5' % e for e in BANDWIDTH_WEIGHT_ENTRIES])

    for test_value in test_values:
      weight_entry = base_weight_entry.replace('Wbe=5', test_value)
      content = get_network_status_document_v3({'bandwidth-weights': weight_entry}, content = True)

      self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
      document = NetworkStatusDocumentV3(content, False)
      self.assertEqual({}, document.bandwidth_weights)

  def test_bandwidth_wights_misordered(self):
    """
    Check that the 'bandwidth-wights' line is rejected if out of order.
    """

    weight_entry = ' '.join(['%s=5' % e for e in reversed(BANDWIDTH_WEIGHT_ENTRIES)])

    content = get_network_status_document_v3({'bandwidth-weights': weight_entry}, content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual({}, document.bandwidth_weights)

  def test_bandwidth_wights_in_vote(self):
    """
    Tries adding a 'bandwidth-wights' line to a vote.
    """

    weight_entry = ' '.join(['%s=5' % e for e in BANDWIDTH_WEIGHT_ENTRIES])
    expected = dict([(e, 5) for e in BANDWIDTH_WEIGHT_ENTRIES])

    content = get_network_status_document_v3({'vote-status': 'vote', 'bandwidth-weights': weight_entry}, content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual(expected, document.bandwidth_weights)

  def test_microdescriptor_signature(self):
    """
    The 'directory-signature' lines both with and without a defined method for
    the signature format.
    """

    # including the signature method field should work

    document = get_network_status_document_v3({
      'network-status-version': '3 microdesc',
      'directory-signature': 'sha256 ' + NETWORK_STATUS_DOCUMENT_FOOTER[2][1],
    })

    self.assertEqual('sha256', document.signatures[0].method)

    # excluding the method should default to sha1

    document = get_network_status_document_v3({
      'network-status-version': '3 microdesc',
    })

    self.assertEqual('sha1', document.signatures[0].method)

  def test_malformed_signature(self):
    """
    Provides malformed or missing content in the 'directory-signature' line.
    """

    test_values = (
      '',
      '\n',
      'blarg',
    )

    for test_value in test_values:
      for test_attr in range(3):
        attrs = [DOC_SIG.identity, DOC_SIG.key_digest, DOC_SIG.signature]
        attrs[test_attr] = test_value

        content = get_network_status_document_v3({'directory-signature': '%s %s\n%s' % tuple(attrs)}, content = True)
        self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
        NetworkStatusDocumentV3(content, False)  # checks that it's still parsable without validation

  def test_with_router_status_entries(self):
    """
    Includes router status entries within the document. This isn't to test the
    RouterStatusEntry parsing but rather the inclusion of it within the
    document.
    """

    entry1 = get_router_status_entry_v3({'s': 'Fast'})
    entry2 = get_router_status_entry_v3({
      'r': 'Nightfae AWt0XNId/OU2xX5xs5hVtDc5Mes 6873oEfM7fFIbxYtwllw9GPDwkA 2013-02-20 11:12:27 85.177.66.233 9001 9030',
      's': 'Valid',
    })

    document = get_network_status_document_v3(routers = (entry1, entry2))

    self.assertTrue(entry1 in document.routers.values())
    self.assertTrue(entry2 in document.routers.values())

    # try with an invalid RouterStatusEntry

    entry3 = RouterStatusEntryV3(get_router_status_entry_v3({'r': 'ugabuga'}, content = True), False)
    content = get_network_status_document_v3(routers = (entry3,), content = True)

    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([entry3], list(document.routers.values()))

    # try including with a microdescriptor consensus

    content = get_network_status_document_v3({'network-status-version': '3 microdesc'}, routers = (entry1,), content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([RouterStatusEntryMicroV3(str(entry1), False)], list(document.routers.values()))

  def test_with_microdescriptor_router_status_entries(self):
    """
    Includes microdescriptor flavored router status entries within the
    document.
    """

    entry1 = get_router_status_entry_micro_v3({'s': 'Fast'})
    entry2 = get_router_status_entry_micro_v3({
      'r': 'tornodeviennasil AcWxDFxrHetHYS5m6/MVt8ZN6AM 2013-03-13 22:09:13 78.142.142.246 443 80',
      's': 'Valid',
    })

    document = get_network_status_document_v3({'network-status-version': '3 microdesc'}, routers = (entry1, entry2))

    self.assertTrue(entry1 in document.routers.values())
    self.assertTrue(entry2 in document.routers.values())

    # try with an invalid RouterStatusEntry

    entry3 = RouterStatusEntryMicroV3(get_router_status_entry_micro_v3({'r': 'ugabuga'}, content = True), False)

    content = get_network_status_document_v3({'network-status-version': '3 microdesc'}, routers = (entry3,), content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([entry3], list(document.routers.values()))

    # try including microdescriptor entry in a normal consensus

    content = get_network_status_document_v3(routers = (entry1,), content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, False)
    self.assertEqual([RouterStatusEntryV3(str(entry1), False)], list(document.routers.values()))

  def test_with_directory_authorities(self):
    """
    Includes a couple directory authorities in the document.
    """

    for is_document_vote in (False, True):
      for is_authorities_vote in (False, True):
        authority1 = get_directory_authority({'contact': 'doctor jekyll'}, is_vote = is_authorities_vote)
        authority2 = get_directory_authority({'contact': 'mister hyde'}, is_vote = is_authorities_vote)

        vote_status = 'vote' if is_document_vote else 'consensus'
        content = get_network_status_document_v3({'vote-status': vote_status}, authorities = (authority1, authority2), content = True)

        if is_document_vote == is_authorities_vote:
          if is_document_vote:
            # votes can only have a single authority

            self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
            document = NetworkStatusDocumentV3(content, validate = False)
          else:
            document = NetworkStatusDocumentV3(content)

          self.assertEqual((authority1, authority2), document.directory_authorities)
        else:
          # authority votes in a consensus or consensus authorities in a vote
          self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)
          document = NetworkStatusDocumentV3(content, validate = False)
          self.assertEqual((authority1, authority2), document.directory_authorities)

  def test_with_legacy_directory_authorities(self):
    """
    Includes both normal authorities and those following the '-legacy' format.
    """

    legacy_content = 'dir-source gabelmoo-legacy 81349FC1F2DBA2C2C11B45CB9706637D480AB913 131.188.40.189 131.188.40.189 80 443'

    authority1 = get_directory_authority({'contact': 'doctor jekyll'}, is_vote = False)
    authority2 = DirectoryAuthority(legacy_content, validate = True, is_vote = False)
    authority3 = get_directory_authority({'contact': 'mister hyde'}, is_vote = False)

    document = get_network_status_document_v3({'vote-status': 'consensus'}, authorities = (authority1, authority2, authority3))

    self.assertEqual((authority1, authority2, authority3), document.directory_authorities)

  def test_authority_validation_flag_propagation(self):
    """
    Includes invalid certificate content in an authority entry. This is testing
    that the 'validate' flag propagages from the document to authority, and
    authority to certificate classes.
    """

    # make the dir-key-published field of the certiciate be malformed
    authority_content = get_directory_authority(is_vote = True, content = True)
    authority_content = authority_content.replace(b'dir-key-published 2011', b'dir-key-published 2011a')
    authority = DirectoryAuthority(authority_content, False, True)

    content = get_network_status_document_v3({'vote-status': 'vote'}, authorities = (authority,), content = True)
    self.assertRaises(ValueError, NetworkStatusDocumentV3, content, True)

    document = NetworkStatusDocumentV3(content, validate = False)
    self.assertEqual((authority,), document.directory_authorities)
