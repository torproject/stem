"""
Unit tests for stem.descriptor.server_descriptor.
"""

import datetime
import io
import pickle
import tarfile
import unittest

import stem.descriptor.server_descriptor
import stem.exit_policy
import stem.prereq
import stem.version
import stem.util.str_tools

from stem.util import str_type
from stem.descriptor.server_descriptor import RelayDescriptor, BridgeDescriptor

from test.mocking import (
  get_relay_server_descriptor,
  get_bridge_server_descriptor,
  CRYPTO_BLOB,
)

from test.unit.descriptor import get_resource

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

TARFILE_FINGERPRINTS = set([
  str_type('B6D83EC2D9E18B0A7A33428F8CFA9C536769E209'),
  str_type('E0BD57A11F00041A9789577C53A1B784473669E4'),
  str_type('1F43EE37A0670301AD9CB555D94AFEC2C89FDE86'),
])


class TestServerDescriptor(unittest.TestCase):
  def test_with_tarfile_path(self):
    """
    Fetch server descriptors via parse_file() for a tarfile path.
    """

    descriptors = list(stem.descriptor.parse_file(get_resource('descriptor_archive.tar')))
    self.assertEqual(3, len(descriptors))

    fingerprints = set([desc.fingerprint for desc in descriptors])
    self.assertEqual(TARFILE_FINGERPRINTS, fingerprints)

  def test_with_tarfile_object(self):
    """
    Fetch server descriptors via parse_file() for a tarfile object.
    """

    # TODO: When dropping python 2.6 support we can go back to using the 'with'
    # keyword here.

    tar_file = tarfile.open(get_resource('descriptor_archive.tar'))
    descriptors = list(stem.descriptor.parse_file(tar_file))
    self.assertEqual(3, len(descriptors))

    fingerprints = set([desc.fingerprint for desc in descriptors])
    self.assertEqual(TARFILE_FINGERPRINTS, fingerprints)
    tar_file.close()

  def test_metrics_descriptor(self):
    """
    Parses and checks our results against a server descriptor from metrics.
    """

    expected_family = set([
      '$0CE3CFB1E9CC47B63EA8869813BF6FAB7D4540C1',
      '$1FD187E8F69A9B74C9202DC16A25B9E7744AB9F6',
      '$74FB5EFA6A46DE4060431D515DC9A790E6AD9A7C',
      '$77001D8DA9BF445B0F81AA427A675F570D222E6A',
      '$B6D83EC2D9E18B0A7A33428F8CFA9C536769E209',
      '$D2F37F46182C23AB747787FD657E680B34EAF892',
      '$E0BD57A11F00041A9789577C53A1B784473669E4',
      '$E5E3E9A472EAF7BE9682B86E92305DB4C71048EF',
    ])

    expected_onion_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJv5IIWQ+WDWYUdyA/0L8qbIkEVH/cwryZWoIaPAzINfrw1WfNZGtBmg
skFtXhOHHqTRN4GPPrZsAIUOQGzQtGb66IQgT4tO/pj+P6QmSCCdTfhvGfgTCsC+
WPi4Fl2qryzTb3QO5r5x7T8OsG2IBUET1bLQzmtbC560SYR49IvVAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_signing_key = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAKwvOXyztVKnuYvpTKt+nS3XIKeO8dVungi8qGoeS+6gkR6lDtGfBTjd
uE9UIkdAl9zi8/1Ic2wsUNHE9jiS0VgeupITGZY8YOyMJJ/xtV1cqgiWhq1dUYaq
51TOtUogtAPgXPh4J+V8HbFFIcCzIh3qCO/xXo+DSHhv7SSif1VpAgMBAAE=
-----END RSA PUBLIC KEY-----"""

    expected_signature = """-----BEGIN SIGNATURE-----
dskLSPz8beUW7bzwDjR6EVNGpyoZde83Ejvau+5F2c6cGnlu91fiZN3suE88iE6e
758b9ldq5eh5mapb8vuuV3uO+0Xsud7IEOqfxdkmk0GKnUX8ouru7DSIUzUL0zqq
Qlx9HNCqCY877ztFRC624ja2ql6A2hBcuoYMbkHjcQ4=
-----END SIGNATURE-----"""

    with open(get_resource('example_descriptor'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0'))

    self.assertEqual('caerSidi', desc.nickname)
    self.assertEqual('A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB', desc.fingerprint)
    self.assertEqual('71.35.133.197', desc.address)
    self.assertEqual(9001, desc.or_port)
    self.assertEqual(None, desc.socks_port)
    self.assertEqual(None, desc.dir_port)
    self.assertEqual(None, desc.ed25519_certificate)
    self.assertEqual(None, desc.ed25519_master_key)
    self.assertEqual(None, desc.ed25519_signature)
    self.assertEqual(b'Tor 0.2.1.30 on Linux x86_64', desc.platform)
    self.assertEqual(stem.version.Version('0.2.1.30'), desc.tor_version)
    self.assertEqual('Linux x86_64', desc.operating_system)
    self.assertEqual(588217, desc.uptime)
    self.assertEqual(datetime.datetime(2012, 3, 1, 17, 15, 27), desc.published)
    self.assertEqual(b'www.atagar.com/contact', desc.contact)
    self.assertEqual(['1', '2'], desc.link_protocols)
    self.assertEqual(['1'], desc.circuit_protocols)
    self.assertEqual(False, desc.hibernating)
    self.assertEqual(False, desc.allow_single_hop_exits)
    self.assertEqual(False, desc.allow_tunneled_dir_requests)
    self.assertEqual(False, desc.extra_info_cache)
    self.assertEqual('D225B728768D7EA4B5587C13A7A9D22EBBEE6E66', desc.extra_info_digest)
    self.assertEqual(['2'], desc.hidden_service_dir)
    self.assertEqual(expected_family, desc.family)
    self.assertEqual(153600, desc.average_bandwidth)
    self.assertEqual(256000, desc.burst_bandwidth)
    self.assertEqual(104590, desc.observed_bandwidth)
    self.assertEqual(stem.exit_policy.ExitPolicy('reject *:*'), desc.exit_policy)
    self.assertEqual(expected_onion_key, desc.onion_key)
    self.assertEqual(None, desc.onion_key_crosscert)
    self.assertEqual(None, desc.ntor_onion_key_crosscert)
    self.assertEqual(None, desc.onion_key_crosscert)
    self.assertEqual(expected_signing_key, desc.signing_key)
    self.assertEqual(expected_signature, desc.signature)
    self.assertEqual([], desc.get_unrecognized_lines())
    self.assertEqual('2C7B27BEAB04B4E2459D89CA6D5CD1CC5F95A689', desc.digest())

  def test_metrics_descriptor_multiple(self):
    """
    Parses and checks our results against a server descriptor from metrics.
    """

    with open(get_resource('metrics_server_desc_multiple'), 'rb') as descriptor_file:
      descriptors = list(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0'))

      self.assertEqual(2, len(descriptors))

      self.assertEqual('anonion', descriptors[0].nickname)
      self.assertEqual('9A5EC5BB866517E53962AF4D3E776536694B069E', descriptors[0].fingerprint)

      self.assertEqual('Unnamed', descriptors[1].nickname)
      self.assertEqual('5366F1D198759F8894EA6E5FF768C667F59AFD24', descriptors[1].fingerprint)

  def test_old_descriptor(self):
    """
    Parses a relay server descriptor from 2005.
    """

    with open(get_resource('old_descriptor'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0', validate = True))

    self.assertEqual('krypton', desc.nickname)
    self.assertEqual('3E2F63E2356F52318B536A12B6445373808A5D6C', desc.fingerprint)
    self.assertEqual('212.37.39.59', desc.address)
    self.assertEqual(8000, desc.or_port)
    self.assertEqual(None, desc.socks_port)
    self.assertEqual(None, desc.dir_port)
    self.assertEqual(b'Tor 0.1.0.14 on FreeBSD i386', desc.platform)
    self.assertEqual(stem.version.Version('0.1.0.14'), desc.tor_version)
    self.assertEqual('FreeBSD i386', desc.operating_system)
    self.assertEqual(64820, desc.uptime)
    self.assertEqual(datetime.datetime(2005, 12, 16, 18, 1, 3), desc.published)
    self.assertEqual(None, desc.contact)
    self.assertEqual(None, desc.link_protocols)
    self.assertEqual(None, desc.circuit_protocols)
    self.assertEqual(True, desc.hibernating)
    self.assertEqual(False, desc.allow_single_hop_exits)
    self.assertEqual(False, desc.allow_tunneled_dir_requests)
    self.assertEqual(False, desc.extra_info_cache)
    self.assertEqual(None, desc.extra_info_digest)
    self.assertEqual(None, desc.hidden_service_dir)
    self.assertEqual(set(), desc.family)
    self.assertEqual(102400, desc.average_bandwidth)
    self.assertEqual(10485760, desc.burst_bandwidth)
    self.assertEqual(0, desc.observed_bandwidth)
    self.assertEqual(datetime.datetime(2005, 12, 16, 18, 0, 48), desc.read_history_end)
    self.assertEqual(900, desc.read_history_interval)
    self.assertEqual(datetime.datetime(2005, 12, 16, 18, 0, 48), desc.write_history_end)
    self.assertEqual(900, desc.write_history_interval)
    self.assertEqual([], desc.get_unrecognized_lines())

    # The read-history and write-history lines are pretty long so just checking
    # the initial contents for the line and parsed values.

    read_values_start = [20774, 489973, 510022, 511163, 20949]
    self.assertEqual(read_values_start, desc.read_history_values[:5])

    write_values_start = [81, 8848, 8927, 8927, 83, 8848, 8931, 8929, 81, 8846]
    self.assertEqual(write_values_start, desc.write_history_values[:10])

  def test_non_ascii_descriptor(self):
    """
    Parses a descriptor with non-ascii content.
    """

    with open(get_resource('non-ascii_descriptor'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0', validate = True))

    self.assertEqual('Coruscant', desc.nickname)
    self.assertEqual('0B9821545C48E496AEED9ECC0DB506C49FF8158D', desc.fingerprint)
    self.assertEqual('88.182.161.122', desc.address)
    self.assertEqual(9001, desc.or_port)
    self.assertEqual(None, desc.socks_port)
    self.assertEqual(9030, desc.dir_port)
    self.assertEqual(b'Tor 0.2.3.25 on Linux', desc.platform)
    self.assertEqual(stem.version.Version('0.2.3.25'), desc.tor_version)
    self.assertEqual('Linux', desc.operating_system)
    self.assertEqual(259738, desc.uptime)
    self.assertEqual(datetime.datetime(2013, 5, 18, 11, 16, 19), desc.published)
    self.assertEqual(b'1024D/04D2E818 L\xc3\xa9na\xc3\xafc Huard <lenaic dot huard AT laposte dot net>', desc.contact)
    self.assertEqual(['1', '2'], desc.link_protocols)
    self.assertEqual(['1'], desc.circuit_protocols)
    self.assertEqual(False, desc.hibernating)
    self.assertEqual(False, desc.allow_single_hop_exits)
    self.assertEqual(False, desc.allow_tunneled_dir_requests)
    self.assertEqual(False, desc.extra_info_cache)
    self.assertEqual('56403D838DE152421CD401B8E57DAD4483A3D56B', desc.extra_info_digest)
    self.assertEqual(['2'], desc.hidden_service_dir)
    self.assertEqual(set(), desc.family)
    self.assertEqual(102400, desc.average_bandwidth)
    self.assertEqual(204800, desc.burst_bandwidth)
    self.assertEqual(122818, desc.observed_bandwidth)
    self.assertEqual(stem.exit_policy.ExitPolicy('reject *:*'), desc.exit_policy)
    self.assertEqual([], desc.get_unrecognized_lines())

    # Make sure that we can get a string representation for this descriptor
    # (having non-unicode content risks a UnicodeEncodeError)...
    #
    # https://trac.torproject.org/8265

    self.assertTrue(isinstance(str(desc), str))

  def test_with_ed25519(self):
    """
    Parses a descriptor with a ed25519 identity key, as added by proposal 228
    (cross certification onionkeys).
    """

    with open(get_resource('server_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = True))

    family = set([
      '$379FB450010D17078B3766C2273303C358C3A442',
      '$3EB46C1D8D8B1C0BBCB6E4F08301EF68B7F5308D',
      '$B0279A521375F3CB2AE210BDBFC645FDD2E1973A',
      '$EC116BCB80565A408CE67F8EC3FE3B0B02C3A065',
    ])

    self.assertEqual('destiny', desc.nickname)
    self.assertEqual('F65E0196C94DFFF48AFBF2F5F9E3E19AAE583FD0', desc.fingerprint)
    self.assertEqual('94.242.246.23', desc.address)
    self.assertEqual(9001, desc.or_port)
    self.assertEqual(None, desc.socks_port)
    self.assertEqual(443, desc.dir_port)
    self.assertTrue('bWPo2fIzo3uOywfoM' in desc.ed25519_certificate)
    self.assertEqual('Z6a1UabSK+N21j6NnyM6N7jssH6DK68qa6W5uB4QpGQ', desc.ed25519_master_key)
    self.assertEqual('w+cKNZTlL7vz/4WgYdFUblzJy3VdTw0mfFK4N3SPFCt20fNKt9SgiZ5V/2ai3kgGsc6oCsyUesSiYtPcTXMLCw', desc.ed25519_signature)
    self.assertEqual(b'Tor 0.2.7.2-alpha-dev on Linux', desc.platform)
    self.assertEqual(stem.version.Version('0.2.7.2-alpha-dev'), desc.tor_version)
    self.assertEqual('Linux', desc.operating_system)
    self.assertEqual(1362680, desc.uptime)
    self.assertEqual(datetime.datetime(2015, 8, 22, 15, 21, 45), desc.published)
    self.assertEqual(b'0x02225522 Frenn vun der Enn (FVDE) <info AT enn DOT lu>', desc.contact)
    self.assertEqual(['1', '2'], desc.link_protocols)
    self.assertEqual(['1'], desc.circuit_protocols)
    self.assertEqual(False, desc.hibernating)
    self.assertEqual(False, desc.allow_single_hop_exits)
    self.assertEqual(False, desc.allow_tunneled_dir_requests)
    self.assertEqual(False, desc.extra_info_cache)
    self.assertEqual('44E9B679AF0B4EB09296985BAF4066AE9CA5BB93', desc.extra_info_digest)
    self.assertEqual(['2'], desc.hidden_service_dir)
    self.assertEqual(family, desc.family)
    self.assertEqual(149715200, desc.average_bandwidth)
    self.assertEqual(1048576000, desc.burst_bandwidth)
    self.assertEqual(51867731, desc.observed_bandwidth)
    self.assertTrue(desc.exit_policy is not None)
    self.assertEqual(stem.exit_policy.MicroExitPolicy('reject 25,465,587,10000,14464'), desc.exit_policy_v6)
    self.assertTrue('MIGJAoGBAKpPOe' in desc.onion_key)
    self.assertTrue('iW8BqwH5VKqZai' in desc.onion_key_crosscert)
    self.assertTrue('AQoABhtwAWemtV' in desc.ntor_onion_key_crosscert)
    self.assertEqual('0', desc.ntor_onion_key_crosscert_sign)
    self.assertTrue('MIGJAoGBAOUS7x' in desc.signing_key)
    self.assertTrue('y72z1dZOYxVQVL' in desc.signature)
    self.assertEqual('B5E441051D139CCD84BC765D130B01E44DAC29AD', desc.digest())
    self.assertEqual([], desc.get_unrecognized_lines())

  def test_bridge_with_ed25519(self):
    """
    Parses a bridge descriptor with ed25519.
    """

    with open(get_resource('bridge_descriptor_with_ed25519'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, validate = True))

    self.assertEqual('ChandlerObfs11', desc.nickname)
    self.assertEqual('678912ABD7398DF8EFC8FA2BC7DEF610710360C4', desc.fingerprint)
    self.assertEqual('10.162.85.172', desc.address)
    self.assertFalse(hasattr(desc, 'ed25519_certificate'))
    self.assertEqual('lgIuiAJCoXPRwWoHgG4ZAoKtmrv47aPr4AsbmESj8AA', desc.ed25519_certificate_hash)
    self.assertEqual('OB/fqLD8lYmjti09R+xXH/D4S2qlizxdZqtudnsunxE', desc.router_digest_sha256)
    self.assertEqual([], desc.get_unrecognized_lines())

  def test_cr_in_contact_line(self):
    """
    Parses a descriptor with a huge contact line containing anomalous carriage
    returns ('\r' entries).
    """

    with open(get_resource('cr_in_contact_line'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0', validate = True))

    self.assertEqual('pogonip', desc.nickname)
    self.assertEqual('6DABD62BC65D4E6FE620293157FC76968DAB9C9B', desc.fingerprint)
    self.assertEqual('75.5.248.48', desc.address)

    # the contact info block is huge so just checking the start and end,
    # including some of the embedded carriage returns

    contact_start = b'jie1 at pacbell dot net -----BEGIN PGP PUBLIC KEY BLOCK-----\rVersion:'
    contact_end = b'YFRk3NhCY=\r=Xaw3\r-----END PGP PUBLIC KEY BLOCK-----'

    self.assertTrue(desc.contact.startswith(contact_start))
    self.assertTrue(desc.contact.endswith(contact_end))

  def test_negative_uptime(self):
    """
    Parses a descriptor where we are tolerant of a negative uptime, and another
    where we shouldn't be.
    """

    with open(get_resource('negative_uptime'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0', validate = True))

    self.assertEqual('TipTor', desc.nickname)
    self.assertEqual('137962D4931DBF08A24E843288B8A155D6D2AEDD', desc.fingerprint)
    self.assertEqual('62.99.247.83', desc.address)

    # modify the relay version so it's after when the negative uptime bug
    # should appear

    descriptor_contents = desc.get_bytes().replace(b'Tor 0.1.1.25', b'Tor 0.1.2.7')
    self.assertRaises(ValueError, stem.descriptor.server_descriptor.RelayDescriptor, descriptor_contents, True)

  def test_bridge_descriptor(self):
    """
    Parses a bridge descriptor.
    """

    with open(get_resource('bridge_descriptor'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'bridge-server-descriptor 1.0', validate = True))

    self.assertEqual('Unnamed', desc.nickname)
    self.assertEqual('4ED573582B16ACDAF6E42AA044A038F83A7F6333', desc.fingerprint)
    self.assertEqual('10.18.111.71', desc.address)
    self.assertEqual(9001, desc.or_port)
    self.assertEqual(None, desc.socks_port)
    self.assertEqual(None, desc.dir_port)
    self.assertEqual(b'Tor 0.2.0.26-rc (r14597) on Linux i686', desc.platform)
    self.assertEqual(stem.version.Version('0.2.0.26-rc'), desc.tor_version)
    self.assertEqual('Linux i686', desc.operating_system)
    self.assertEqual(204, desc.uptime)
    self.assertEqual(datetime.datetime(2008, 5, 20, 19, 45, 0), desc.published)
    self.assertEqual(None, desc.contact)
    self.assertEqual(['1', '2'], desc.link_protocols)
    self.assertEqual(['1'], desc.circuit_protocols)
    self.assertEqual(False, desc.hibernating)
    self.assertEqual(False, desc.allow_single_hop_exits)
    self.assertEqual(False, desc.allow_tunneled_dir_requests)
    self.assertEqual(True, desc.extra_info_cache)
    self.assertEqual('BB1F13AA431421BEA29B840A2E33BB1C31C2990B', desc.extra_info_digest)
    self.assertEqual(None, desc.hidden_service_dir)
    self.assertEqual(set(), desc.family)
    self.assertEqual(3220480, desc.average_bandwidth)
    self.assertEqual(6441984, desc.burst_bandwidth)
    self.assertEqual(59408, desc.observed_bandwidth)
    self.assertEqual(stem.exit_policy.ExitPolicy('reject *:*'), desc.exit_policy)
    self.assertEqual('00F1CD29AD308A59A9AB5A88B49ECB46E0F215FD', desc.digest())
    self.assertEqual([], desc.get_unrecognized_lines())

  def test_minimal_relay_descriptor(self):
    """
    Basic sanity check that we can parse a relay server descriptor with minimal
    attributes.
    """

    desc = get_relay_server_descriptor()

    self.assertEqual('caerSidi', desc.nickname)
    self.assertEqual('71.35.133.197', desc.address)
    self.assertEqual(None, desc.fingerprint)
    self.assertTrue(CRYPTO_BLOB in desc.onion_key)

  def test_with_opt(self):
    """
    Includes an 'opt <keyword> <value>' entry.
    """

    desc = get_relay_server_descriptor({'opt': 'contact www.atagar.com/contact/'})
    self.assertEqual(b'www.atagar.com/contact/', desc.contact)

  def test_unrecognized_line(self):
    """
    Includes unrecognized content in the descriptor.
    """

    desc = get_relay_server_descriptor({'pepperjack': 'is oh so tasty!'})
    self.assertEqual(['pepperjack is oh so tasty!'], desc.get_unrecognized_lines())

  def test_proceeding_line(self):
    """
    Includes a line prior to the 'router' entry.
    """

    desc_text = b'hibernate 1\n' + get_relay_server_descriptor(content = True)
    self._expect_invalid_attr(desc_text)

  def test_trailing_line(self):
    """
    Includes a line after the 'router-signature' entry.
    """

    desc_text = get_relay_server_descriptor(content = True) + b'\nhibernate 1'
    self._expect_invalid_attr(desc_text)

  def test_nickname_missing(self):
    """
    Constructs with a malformed router entry.
    """

    desc_text = get_relay_server_descriptor({'router': ' 71.35.133.197 9001 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'nickname')

  def test_nickname_too_long(self):
    """
    Constructs with a nickname that is an invalid length.
    """

    desc_text = get_relay_server_descriptor({'router': 'saberrider2008ReallyLongNickname 71.35.133.197 9001 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'nickname')

  def test_nickname_invalid_char(self):
    """
    Constructs with an invalid relay nickname.
    """

    desc_text = get_relay_server_descriptor({'router': '$aberrider2008 71.35.133.197 9001 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'nickname')

  def test_address_malformed(self):
    """
    Constructs with an invalid ip address.
    """

    desc_text = get_relay_server_descriptor({'router': 'caerSidi 371.35.133.197 9001 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'address')

  def test_port_too_high(self):
    """
    Constructs with an ORPort that is too large.
    """

    desc_text = get_relay_server_descriptor({'router': 'caerSidi 71.35.133.197 900001 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'or_port')

  def test_port_malformed(self):
    """
    Constructs with an ORPort that isn't numeric.
    """

    desc_text = get_relay_server_descriptor({'router': 'caerSidi 71.35.133.197 900a1 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'or_port')

  def test_port_newline(self):
    """
    Constructs with a newline replacing the ORPort.
    """

    desc_text = get_relay_server_descriptor({'router': 'caerSidi 71.35.133.197 \n 0 0'}, content = True)
    self._expect_invalid_attr(desc_text, 'or_port')

  def test_platform_empty(self):
    """
    Constructs with an empty platform entry.
    """

    desc_text = get_relay_server_descriptor({'platform': ''}, content = True)
    desc = RelayDescriptor(desc_text, validate = False)
    self.assertEqual(b'', desc.platform)

    # does the same but with 'platform ' replaced with 'platform'
    desc_text = desc_text.replace(b'platform ', b'platform')
    desc = RelayDescriptor(desc_text, validate = False)
    self.assertEqual(b'', desc.platform)

  def test_platform_for_node_tor(self):
    """
    Parse a platform line belonging to a node-Tor relay.
    """

    desc = get_relay_server_descriptor({'platform': 'node-Tor 0.1.0 on Linux x86_64'})
    self.assertEqual(b'node-Tor 0.1.0 on Linux x86_64', desc.platform)
    self.assertEqual(stem.version.Version('0.1.0'), desc.tor_version)
    self.assertEqual('Linux x86_64', desc.operating_system)

  def test_protocols_no_circuit_versions(self):
    """
    Constructs with a protocols line without circuit versions.
    """

    desc_text = get_relay_server_descriptor({'opt': 'protocols Link 1 2'}, content = True)
    self._expect_invalid_attr(desc_text, 'circuit_protocols')

  @patch('stem.prereq.is_crypto_available', Mock(return_value = False))
  def test_published_leap_year(self):
    """
    Constructs with a published entry for a leap year, and when the date is
    invalid.
    """

    desc_text = get_relay_server_descriptor({'published': '2011-02-29 04:03:19'}, content = True)
    self._expect_invalid_attr(desc_text, 'published')

    desc_text = get_relay_server_descriptor({'published': '2012-02-29 04:03:19'}, content = True)
    expected_published = datetime.datetime(2012, 2, 29, 4, 3, 19)
    self.assertEqual(expected_published, RelayDescriptor(desc_text).published)

  def test_published_no_time(self):
    """
    Constructs with a published entry without a time component.
    """

    desc_text = get_relay_server_descriptor({'published': '2012-01-01'}, content = True)
    self._expect_invalid_attr(desc_text, 'published')

  def test_read_and_write_history(self):
    """
    Parses a read-history and write-history entry. This is now a deprecated
    field for relay server descriptors but is still found in archives and
    extra-info descriptors.
    """

    for field in ('read-history', 'write-history'):
      value = '2005-12-16 18:00:48 (900 s) 81,8848,8927,8927,83,8848'
      desc = get_relay_server_descriptor({'opt %s' % field: value})

      if field == 'read-history':
        attr = (desc.read_history_end, desc.read_history_interval, desc.read_history_values)
      else:
        attr = (desc.write_history_end, desc.write_history_interval, desc.write_history_values)

      expected_end = datetime.datetime(2005, 12, 16, 18, 0, 48)
      expected_values = [81, 8848, 8927, 8927, 83, 8848]

      self.assertEqual(expected_end, attr[0])
      self.assertEqual(900, attr[1])
      self.assertEqual(expected_values, attr[2])

  def test_read_history_empty(self):
    """
    Parses a read-history with an empty value.
    """

    value = '2005-12-17 01:23:11 (900 s) '
    desc = get_relay_server_descriptor({'opt read-history': value})
    self.assertEqual(datetime.datetime(2005, 12, 17, 1, 23, 11), desc.read_history_end)
    self.assertEqual(900, desc.read_history_interval)
    self.assertEqual([], desc.read_history_values)

  @patch('stem.prereq.is_crypto_available', Mock(return_value = False))
  def test_annotations(self):
    """
    Checks that content before a descriptor are parsed as annotations.
    """

    desc_text = b'@pepperjack very tasty\n@mushrooms not so much\n'
    desc_text += get_relay_server_descriptor(content = True)
    desc_text += b'\ntrailing text that should be invalid, ho hum'

    # running _parse_file should provide an iterator with a single descriptor
    desc_iter = stem.descriptor.server_descriptor._parse_file(io.BytesIO(desc_text), validate = True)
    self.assertRaises(ValueError, list, desc_iter)

    desc_text = b'@pepperjack very tasty\n@mushrooms not so much\n'
    desc_text += get_relay_server_descriptor(content = True)
    desc_iter = stem.descriptor.server_descriptor._parse_file(io.BytesIO(desc_text))

    desc_entries = list(desc_iter)
    self.assertEqual(1, len(desc_entries))
    desc = desc_entries[0]

    self.assertEqual('caerSidi', desc.nickname)
    self.assertEqual(b'@pepperjack very tasty', desc.get_annotation_lines()[0])
    self.assertEqual(b'@mushrooms not so much', desc.get_annotation_lines()[1])
    self.assertEqual({b'@pepperjack': b'very tasty', b'@mushrooms': b'not so much'}, desc.get_annotations())
    self.assertEqual([], desc.get_unrecognized_lines())

  def test_duplicate_field(self):
    """
    Constructs with a field appearing twice.
    """

    desc_text = get_relay_server_descriptor({'<replace>': ''}, content = True)
    desc_text = desc_text.replace(b'<replace>', b'contact foo\ncontact bar')
    self._expect_invalid_attr(desc_text, 'contact', b'foo')

  def test_missing_required_attr(self):
    """
    Test making a descriptor with a missing required attribute.
    """

    for attr in stem.descriptor.server_descriptor.REQUIRED_FIELDS:
      desc_text = get_relay_server_descriptor(exclude = [attr], content = True)
      self.assertRaises(ValueError, RelayDescriptor, desc_text, True)

      # check that we can still construct it without validation
      desc = RelayDescriptor(desc_text, validate = False)

      # for one of them checks that the corresponding values are None
      if attr == 'router':
        self.assertEqual(None, desc.nickname)
        self.assertEqual(None, desc.address)
        self.assertEqual(None, desc.or_port)
        self.assertEqual(None, desc.socks_port)
        self.assertEqual(None, desc.dir_port)

  def test_fingerprint_invalid(self):
    """
    Checks that, with a correctly formed fingerprint, we'll fail validation if
    it doesn't match the hash of our signing key.
    """

    fingerprint = '4F0C 867D F0EF 6816 0568 C826 838F 482C EA7C FE45'
    desc_text = get_relay_server_descriptor({'opt fingerprint': fingerprint}, content = True)
    self._expect_invalid_attr(desc_text, 'fingerprint', fingerprint.replace(' ', ''))

  def test_ipv6_policy(self):
    """
    Checks a 'ipv6-policy' line.
    """

    expected = stem.exit_policy.MicroExitPolicy('accept 22-23,53,80,110')
    desc = get_relay_server_descriptor({'ipv6-policy': 'accept 22-23,53,80,110'})
    self.assertEqual(expected, desc.exit_policy_v6)

  def test_ntor_onion_key(self):
    """
    Checks a 'ntor-onion-key' line.
    """

    desc = get_relay_server_descriptor({'ntor-onion-key': 'Od2Sj3UXFyDjwESLXk6fhatqW9z/oBL/vAKJ+tbDqUU='})
    self.assertEqual('Od2Sj3UXFyDjwESLXk6fhatqW9z/oBL/vAKJ+tbDqUU=', desc.ntor_onion_key)

  def test_minimal_bridge_descriptor(self):
    """
    Basic sanity check that we can parse a descriptor with minimal attributes.
    """

    desc = get_bridge_server_descriptor()

    self.assertEqual('Unnamed', desc.nickname)
    self.assertEqual('10.45.227.253', desc.address)
    self.assertEqual(None, desc.fingerprint)
    self.assertEqual('006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4', desc.digest())

    # check that we don't have crypto fields
    self.assertRaises(AttributeError, getattr, desc, 'onion_key')
    self.assertRaises(AttributeError, getattr, desc, 'signing_key')
    self.assertRaises(AttributeError, getattr, desc, 'signature')

  def test_bridge_unsanitized(self):
    """
    Targeted check that individual unsanitized attributes will be detected.
    """

    unsanitized_attr = [
      {'router': 'Unnamed 75.45.227.253 9001 0 0'},
      {'contact': 'Damian'},
      {'or-address': '71.35.133.197:9001'},
      {'or-address': '[12ab:2e19:3bcf::02:9970]:9001'},
      {'onion-key': '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB},
      {'signing-key': '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB},
      {'router-signature': '\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB},
    ]

    for attr in unsanitized_attr:
      desc = get_bridge_server_descriptor(attr)
      self.assertFalse(desc.is_scrubbed())

  def test_bridge_unsanitized_relay(self):
    """
    Checks that parsing a normal relay descriptor as a bridge will fail due to
    its unsanatized content.
    """

    desc_text = get_relay_server_descriptor({'router-digest': '006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4'}, content = True)
    desc = BridgeDescriptor(desc_text)
    self.assertFalse(desc.is_scrubbed())

  def test_router_digest(self):
    """
    Constructs with a router-digest line with both valid and invalid contents.
    """

    # checks with valid content

    router_digest = '068A2E28D4C934D9490303B7A645BA068DCA0504'
    desc = get_bridge_server_descriptor({'router-digest': router_digest})
    self.assertEqual(router_digest, desc.digest())

    # checks when missing

    desc_text = get_bridge_server_descriptor(exclude = ['router-digest'], content = True)
    self.assertRaises(ValueError, BridgeDescriptor, desc_text, True)

    # check that we can still construct it without validation
    desc = BridgeDescriptor(desc_text, validate = False)
    self.assertEqual(None, desc.digest())

    # checks with invalid content

    test_values = (
      '',
      '006FD96BA35E7785A6A3B8B75FE2E2435A13BDB44',
      '006FD96BA35E7785A6A3B8B75FE2E2435A13BDB',
      '006FD96BA35E7785A6A3B8B75FE2E2435A13BDBH',
    )

    for value in test_values:
      desc_text = get_bridge_server_descriptor({'router-digest': value}, content = True)
      self.assertRaises(ValueError, BridgeDescriptor, desc_text, True)

      desc = BridgeDescriptor(desc_text, validate = False)
      self.assertEqual(None, desc.digest())

  def test_or_address_v4(self):
    """
    Constructs a bridge descriptor with a sanatized IPv4 or-address entry.
    """

    desc = get_bridge_server_descriptor({'or-address': '10.45.227.253:9001'})
    self.assertEqual([('10.45.227.253', 9001, False)], desc.or_addresses)

  def test_or_address_v6(self):
    """
    Constructs a bridge descriptor with a sanatized IPv6 or-address entry.
    """

    desc = get_bridge_server_descriptor({'or-address': '[fd9f:2e19:3bcf::02:9970]:9001'})
    self.assertEqual([('fd9f:2e19:3bcf::02:9970', 9001, True)], desc.or_addresses)

  def test_or_address_multiple(self):
    """
    Constructs a bridge descriptor with multiple or-address entries and multiple ports.
    """

    desc_text = b'\n'.join((get_bridge_server_descriptor(content = True),
                            b'or-address 10.45.227.253:9001',
                            b'or-address [fd9f:2e19:3bcf::02:9970]:443'))

    expected_or_addresses = [
      ('10.45.227.253', 9001, False),
      ('fd9f:2e19:3bcf::02:9970', 443, True),
    ]

    desc = BridgeDescriptor(desc_text)
    self.assertEqual(expected_or_addresses, desc.or_addresses)

  def _expect_invalid_attr(self, desc_text, attr = None, expected_value = None):
    """
    Asserts that construction will fail due to desc_text having a malformed
    attribute. If an attr is provided then we check that it matches an expected
    value when we're constructed without validation.
    """

    self.assertRaises(ValueError, RelayDescriptor, desc_text, True)
    desc = RelayDescriptor(desc_text, validate = False)

    if attr:
      # check that the invalid attribute matches the expected value when
      # constructed without validation

      self.assertEqual(expected_value, getattr(desc, attr))
    else:
      # check a default attribute
      self.assertEqual('caerSidi', desc.nickname)

  def test_pickleability(self):
    """
    Checks that we can unpickle lazy loaded server descriptors.
    """

    with open(get_resource('example_descriptor'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0'))

      encoded_desc = pickle.dumps(desc)
      restored_desc = pickle.loads(encoded_desc)

      self.assertEqual('caerSidi', restored_desc.nickname)
      self.assertEqual('A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB', restored_desc.fingerprint)
      self.assertEqual('71.35.133.197', restored_desc.address)
      self.assertEqual(9001, restored_desc.or_port)
      self.assertEqual(None, restored_desc.socks_port)
