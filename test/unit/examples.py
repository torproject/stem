"""
Exercise the code in our examples directory.
"""

import base64
import binascii
import functools
import io
import os
import re
import sys
import unittest

import stem.socket
import stem.util.system
import stem.version
import test
import test.require

from stem.control import Controller, Listener
from stem.descriptor.bandwidth_file import BandwidthFile
from stem.descriptor.extrainfo_descriptor import RelayExtraInfoDescriptor
from stem.descriptor.hidden_service import HiddenServiceDescriptorV2
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.router_status_entry import RouterStatusEntryV2, RouterStatusEntryV3
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.directory import DIRECTORY_AUTHORITIES
from stem.exit_policy import ExitPolicy
from stem.response import ControlMessage
from stem.util.connection import Connection, Resolver
from unittest.mock import Mock, mock_open, patch

EXAMPLE_DIR = os.path.join(test.STEM_BASE, 'docs', '_static', 'example')
DESC_DIR = os.path.join(test.STEM_BASE, 'test', 'unit', 'descriptor', 'data')

UNTESTED = (
  # client usage demos don't have much non-stem code

  'client_usage_using_pycurl',
  'client_usage_using_socksipy',
  'reading_twitter',
)

EXPECTED_BANDWIDTH_STATS = """\
Relay FDCF49562E65B1CC219410009BD48A9EED387C77
  bw = 1
  bw_mean = 807445
  bw_median = 911047
  consensus_bandwidth = 1190000
  node_id = $FDCF49562E65B1CC219410009BD48A9EED387C77

Relay BD4172533C3F7271ABCCD9F057E06FD91547C42B
  bw = 1
  bw_mean = 631049
  bw_median = 622052
  consensus_bandwidth = 55000
  node_id = $BD4172533C3F7271ABCCD9F057E06FD91547C42B

"""

EXPECTED_SERVER_DESC_BENCHMARK_PREFIX = """\
Finished measure_average_advertised_bandwidth('%s')
  Total time: 0 seconds
  Processed server descriptors: 5
  Average advertised bandwidth: 313183
  Time per server descriptor:
""".rstrip()

EXPECTED_EXTRAINFO_BENCHMARK_PREFIX = """\
Finished measure_countries_v3_requests('%s')
  Total time: 0 seconds
  Processed extrainfo descriptors: 7
  Number of countries: 6
  Time per extrainfo descriptor:
""".rstrip()

EXPECTED_CONSENSUS_BENCHMARK_PREFIX = """\
Finished measure_average_relays_exit('%s')
  Total time: 0 seconds
  Processed 2 consensuses with 243 router status entries
  Total exits: 28 (0.12%%)
  Time per consensus:
""".rstrip()

EXPECTED_MICRODESC_BENCHMARK_PREFIX = """\
Finished measure_fraction_relays_exit_80_microdescriptors('%s')
  Total time: 0 seconds
  Processed microdescriptors: 3
  Total exits to port 80: 1 (0.33%%)
  Time per microdescriptor:
""".rstrip()

EXPECTED_CHECK_DIGESTS_OK = """
Server descriptor digest is correct
Extrainfo descriptor digest is correct
"""

EXPECTED_CHECK_DIGESTS_BAD = """
Server descriptor digest invalid, expected A106452D87BD7B803B6CE916291ED368DC5BD091 but is %s
Extrainfo descriptor digest is correct
"""

EXPECTED_COLLECTOR_CACHING = """\
  krypton (3E2F63E2356F52318B536A12B6445373808A5D6C)
  dizum (7EA6EAD6FD83083C538F44038BBFA077587DD755)
  flubber (5C2124E6C5DD75C3C17C03EEA5A51812773DE671)
"""

EXPECTED_COLLECTOR_READING = """\
1 relays published an exiting policy today...

  caerSidi (4F0C867DF0EF68160568C826838F482CEA7CFE44)
"""

EXPECTED_COMPARE_FLAGS = """\
moria1 has the Running flag but maatuska doesn't: 546C54E2A89D88E0794D04AECBF1AC8AC9DA81DE
maatuska has the Running flag but moria1 doesn't: 6871F682350BA931838C0EC1E4A23044DAE06A73
maatuska has the Running flag but moria1 doesn't: 92FCB6748A40E6088E22FBAB943AB2DD743EA818
moria1 has the Running flag but maatuska doesn't: DCAEC3D069DC39AAE43D13C8AF31B5645E05ED61
maatuska has the Running flag but moria1 doesn't: E2BB13AA2F6960CD93ABE5257A825687F3973C62
"""

EXPECTED_DOWNLOAD_DESCRIPTOR_UNKNOWN_TYPE = """\
Downloading kaboom descriptor from 128.31.0.34:9131...

'kaboom' is not a recognized descriptor type, options are: server, extrainfo, consensus
"""

EXPECTED_DOWNLOAD_DESCRIPTOR_PREFIX = """\
Downloading server descriptor from 1.2.3.4:443...

router caerSidi 71.35.133.197 9001 0 0
"""

EXPECTED_EPHEMEREAL_HIDDEN_SERVICES = """\
 * Connecting to tor
 * Our service is available at my-service.onion, press ctrl+c to quit
 * Shutting down our hidden service
"""

EXPECTED_EXIT_USED = """\
Tracking requests for tor exits. Press 'enter' to end.

Exit relay for our connection to 64.15.112.44:80
  address: 31.172.30.2:443
  fingerprint: A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7
  nickname: chaoscomputerclub19
  locale: unknown

"""

EXPECTED_INTRODUCTION_POINTS = """\
DuckDuckGo's introduction points are...

  178.62.222.129:443 => iwki77xtbvp6qvedfrwdzncxs3ckayeu
  46.4.174.52:443 => em4gjk6eiiualhmlyiifrzc7lbtrsbip
  62.210.82.169:443 => jqhfl364x3upe6lqnxizolewlfrsw2zy
"""

EXPECTED_LIST_CIRCUITS = """\

Circuit 4 (GENERAL)
 |- B1FA7D51B8B6F0CB585D944F450E7C06EDE7E44C (ByTORAndTheSnowDog, 173.209.180.61)
 |- 0DD9935C5E939CFA1E07B8DDA6D91C1A2A9D9338 (afo02, 87.238.194.176)
 +- DB3B1CFBD3E4D97B84B548ADD5B9A31451EEC4CC (edwardsnowden3, 109.163.234.10)

Circuit 6 (GENERAL)
 |- B1FA7D51B8B6F0CB585D944F450E7C06EDE7E44C (ByTORAndTheSnowDog, 173.209.180.61)
 |- EC01CB4766BADC1611678555CE793F2A7EB2D723 (sprockets, 46.165.197.96)
 +- 9EA317EECA56BDF30CAEB208A253FB456EDAB1A0 (bolobolo1, 96.47.226.20)

Circuit 10 (GENERAL)
 |- B1FA7D51B8B6F0CB585D944F450E7C06EDE7E44C (ByTORAndTheSnowDog, 173.209.180.61)
 |- 00C2C2A16AEDB51D5E5FB7D6168FC66B343D822F (ph3x, 86.59.119.83)
 +- 65242C91BFF30F165DA4D132C81A9EBA94B71D62 (torexit16, 176.67.169.171)
"""

EXPECTED_MANUAL_CONFIG_OPTIONS = """\
Downloading tor's manual information, please wait...
  done

Which tor configuration would you like to learn about?  (press ctrl+c to quit)

IPv6Exit 0|1
Allow clients to use us for IPv6 traffic

Full Description:

If set, and we are an exit node, allow clients to use us for IPv6 traffic. When this option is set and ExitRelay is auto, we act as if ExitRelay is 1. (Default: 0)

"""

EXPECTED_OUTDATED_RELAYS = """\
Checking for outdated relays...

  0.1.0           Sambuddha Basu

2 outdated relays found, 1 had contact information
"""

EXPECTED_PERSISTING_A_CONSENSUS = """\
A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB: caerSidi
"""

EXPECTED_RELAY_CONNECTIONS_HELP = """\
usage: run_tests.py [-h] [--ctrlport CTRLPORT] [--resolver RESOLVER]

{options}:
  -h, --help           show this help message and exit
  --ctrlport CTRLPORT  default: 9051 or 9151
  --resolver RESOLVER  default: autodetected
""".format(options="options" if sys.version_info >= (3, 10) else "optional arguments")

EXPECTED_RELAY_CONNECTIONS = """\
 1.2.3.4   uptime: 00:50   flags: Fast, Stable

+------------------------------+------+------+
| Type                         | IPv4 | IPv6 |
+------------------------------+------+------+
| Inbound to our ORPort        |    1 |    0 |
| Inbound to our DirPort       |    2 |    0 |
| Inbound to our ControlPort   |    1 |    0 |
| Outbound uncategorized       |    1 |    0 |
+------------------------------+------+------+
| Total                        |    5 |    0 |
+------------------------------+------+------+

"""

EXPECTED_RUNNING_HIDDEN_SERVICE = """\
 * Connecting to tor
 * Creating our hidden service in /home/atagar/.tor/hello_world
 * Our service is available at uxiuaxejc3sxrb6i.onion, press ctrl+c to quit
 * Shutting down our hidden service
"""

EXPECTED_TOR_DESCRIPTORS = """\
1. speedyexit (102.13 KB/s)
2. speedyexit (102.13 KB/s)
3. speedyexit (102.13 KB/s)
"""

EXPECTED_UTILITIES = """\
Our platform supports connection resolution via: netstat (picked netstat)
Tor is running with pid 12345

Connections:

  17.17.17.17:4369 => 34.34.34.34:8738
  18.18.18.18:443 => 35.35.35.35:4281
"""

EXPECTED_VOTES_BY_BANDWIDTH_AUTHORITIES = """\
Getting gabelmoo's vote from http://131.188.40.189:80/tor/status-vote/current/authority:
  5935 measured entries and 1332 unmeasured
Getting moria1's vote from http://128.31.0.39:9131/tor/status-vote/current/authority:
  6647 measured entries and 625 unmeasured
Getting maatuska's vote from http://171.25.193.9:443/tor/status-vote/current/authority:
  6313 measured entries and 1112 unmeasured
"""

EXPECTED_WORDS_WITH = """\
Words with 'hel' include...

hello                         hellena
"""


def _make_circ_event(circ_id, hop1, hop2, hop3):
  path = '$%s=%s,$%s=%s,$%s=%s' % (hop1[0], hop1[1], hop2[0], hop2[1], hop3[0], hop3[1])
  content = '650 CIRC %i BUILT %s PURPOSE=GENERAL' % (circ_id, path)
  return ControlMessage.from_str(content, 'EVENT', normalize = True)


def _download_of(desc):
  query = Mock()
  query.run.return_value = [desc]
  return Mock(return_value = query)


class TestExamples(unittest.TestCase):
  def setUp(self):
    self.original_path = list(sys.path)
    sys.path.append(EXAMPLE_DIR)

  def tearDown(self):
    sys.path = self.original_path

    # Ensure we don't cache a Mock object as our downloader. Otherwise future
    # tests will understandably be very sad. :P

    stem.descriptor.remote.SINGLETON_DOWNLOADER = None

  def test_everything_is_tested(self):
    """
    Ensure we have tests for all our examples.
    """

    all_examples = set([os.path.basename(path)[:-3] for path in stem.util.system.files_with_suffix(EXAMPLE_DIR, '.py')])
    tested_examples = set([method[5:] for method in dir(self) if method.startswith('test_') and not method.startswith('test_everything_')])

    extra = sorted(tested_examples.difference(all_examples))
    missing = sorted(all_examples.difference(tested_examples).difference(UNTESTED))

    if extra:
      self.fail("Changed our examples directory? We test the following which are not present: %s" % ', '.join(extra))

    if missing:
      self.fail("Changed our examples directory? The following are untested: %s" % ', '.join(missing))

  def test_everything_is_referenced(self):
    """
    Ensure that all our examples are referenced our website. Otherwise they're
    dead code.
    """

    all_examples = set([os.path.basename(path)[:-3] for path in stem.util.system.files_with_suffix(EXAMPLE_DIR, '.py')])

    include_regex = re.compile('.. literalinclude:: /_static/example/(\\S*).py')
    referenced_examples = set()

    for path in stem.util.system.files_with_suffix(os.path.join(test.STEM_BASE, 'docs'), '.rst'):
      with open(path) as example_file:
        referenced_examples.update(include_regex.findall(example_file.read()))

    for path in stem.util.system.files_with_suffix(os.path.join(test.STEM_BASE, 'stem'), '.py'):
      with open(path) as source_file:
        referenced_examples.update(include_regex.findall(source_file.read()))

    extra = sorted(referenced_examples.difference(all_examples))
    missing = sorted(all_examples.difference(referenced_examples))

    missing.remove('benchmark_stem')  # expanded copy of benchmark_server_descriptor_stem.py

    if extra:
      self.fail("Changed our documentation? We reference the following examples which are not present: %s" % ', '.join(extra))

    if missing:
      self.fail("Changed our documntation? The following examples are unreferenced: %s" % ', '.join(missing))

  @patch('stem.descriptor.remote.get_bandwidth_file')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_bandwidth_stats(self, stdout_mock, get_bandwidth_file_mock):
    get_bandwidth_file_mock().run.return_value = [BandwidthFile.create({
      'content': [
        'bw=1 bw_mean=807445 bw_median=911047 consensus_bandwidth=1190000 node_id=$FDCF49562E65B1CC219410009BD48A9EED387C77',
        'bw=1 bw_mean=631049 bw_median=622052 consensus_bandwidth=55000 node_id=$BD4172533C3F7271ABCCD9F057E06FD91547C42B',
      ],
    })]

    import bandwidth_stats
    self.assertEqual(EXPECTED_BANDWIDTH_STATS, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = io.StringIO)
  def test_benchmark_server_descriptor_stem(self, stdout_mock):
    import benchmark_server_descriptor_stem as module

    path = os.path.join(DESC_DIR, 'collector', 'server-descriptors-2005-12-cropped.tar')
    expected_prefix = EXPECTED_SERVER_DESC_BENCHMARK_PREFIX % path

    module.measure_average_advertised_bandwidth(path)

    self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

  def test_benchmark_stem(self):
    import benchmark_stem as module

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'server-descriptors-2005-12-cropped.tar')
      expected_prefix = EXPECTED_SERVER_DESC_BENCHMARK_PREFIX % path

      module.measure_average_advertised_bandwidth(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'extra-infos-2019-04-cropped.tar')
      expected_prefix = EXPECTED_EXTRAINFO_BENCHMARK_PREFIX % path

      module.measure_countries_v3_requests(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'consensuses-2018-06-cropped.tar')
      expected_prefix = EXPECTED_CONSENSUS_BENCHMARK_PREFIX % path

      module.measure_average_relays_exit(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      path = os.path.join(DESC_DIR, 'collector', 'microdescs-2019-05-cropped.tar')
      expected_prefix = EXPECTED_MICRODESC_BENCHMARK_PREFIX % path

      module.measure_fraction_relays_exit_80_microdescriptors(path)
      self.assertTrue(stdout_mock.getvalue().startswith(expected_prefix))

  @patch('time.sleep')
  @patch('stem.control.Controller.authenticate', Mock())
  @patch('stem.control.Controller.is_alive', Mock(return_value = True))
  @patch('stem.control.Controller.from_port')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_broken_listener(self, stdout_mock, from_port_mock, sleep_mock):
    controller = Controller(stem.socket.ControlSocket())
    from_port_mock.return_value = controller

    # emits a BW event when the example runs time.sleep()

    bw_event = ControlMessage.from_str('650 BW 15 25', 'EVENT', normalize = True)
    sleep_mock.side_effect = lambda duration: controller._handle_event(bw_event)

    import broken_listener

    self.assertEqual('start of broken_handler\n', stdout_mock.getvalue())

  @test.require.cryptography
  def test_check_digests(self):
    import check_digests as module
    fingerprint = 'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB'

    extrainfo_desc = RelayExtraInfoDescriptor.create()
    server_desc = RelayDescriptor.create({'extra-info-digest': extrainfo_desc.digest()}, sign = True)

    encoded_digest = base64.b64encode(binascii.unhexlify(server_desc.digest())).rstrip(b'=')

    consensus_desc = RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s %s 2012-08-06 11:19:31 71.35.150.29 9001 0' % encoded_digest.decode('utf-8'),
    })

    bad_consensus_desc = RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    })

    with patch('stem.descriptor.remote.get_server_descriptors', _download_of(server_desc)):
      with patch('stem.descriptor.remote.get_extrainfo_descriptors', _download_of(extrainfo_desc)):
        # correctly signed descriptors

        with patch('stem.descriptor.remote.get_consensus', _download_of(consensus_desc)):
          with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
            module.validate_relay(fingerprint)
            self.assertEqual(EXPECTED_CHECK_DIGESTS_OK, stdout_mock.getvalue())

        # incorrect server descriptor digest

        with patch('stem.descriptor.remote.get_consensus', _download_of(bad_consensus_desc)):
          with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
            module.validate_relay(fingerprint)
            self.assertEqual(EXPECTED_CHECK_DIGESTS_BAD % server_desc.digest(), stdout_mock.getvalue())

  @patch('stem.descriptor.collector.File.download', Mock())
  @patch('stem.descriptor.collector.CollecTor.files')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_collector_caching(self, stdout_mock, files_mock):
    files_mock.return_value = [stem.descriptor.collector.File(
     'archive/relay-descriptors/server-descriptors/server-descriptors-2005-12.tar',
      ['server-descriptor 1.0'],
      1348620,
      '0RrqB5aMY46vTeEHYqnbPVFGZQi1auJkzyHyt0NNDcw=',
      '2005-12-15 01:42',
      '2005-12-17 11:06',
      '2016-06-24 08:12',
    )]

    server_desc = list(stem.descriptor.parse_file(os.path.join(DESC_DIR, 'collector', 'server-descriptors-2005-12-cropped.tar')))

    with patch('stem.descriptor.parse_file', Mock(return_value = server_desc)):
      import collector_caching

    self.assertEqual(EXPECTED_COLLECTOR_CACHING, stdout_mock.getvalue())

  @patch('stem.descriptor.collector.get_server_descriptors')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_collector_reading(self, stdout_mock, server_desc_mock):
    server_desc_mock.return_value = [
      RelayDescriptor.create({
        'router': 'caerSidi 71.35.133.197 9001 0 0',
        'fingerprint': '4F0C 867D F0EF 6816 0568 C826 838F 482C EA7C FE44',
      }, exit_policy = ExitPolicy('accept *:*')),
    ]

    import collector_reading

    self.assertEqual(EXPECTED_COLLECTOR_READING, stdout_mock.getvalue())

  @patch('stem.directory.Authority.from_cache')
  @patch('stem.descriptor.remote.Query')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_compare_flags(self, stdout_mock, query_mock, authorities_mock):
    authorities_mock().items.return_value = [
      ('moria1', DIRECTORY_AUTHORITIES['moria1']),
      ('maatuska', DIRECTORY_AUTHORITIES['maatuska']),
    ]

    r_line = 'caerSidi %s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0'

    moria1_consensus = NetworkStatusDocumentV3.create(routers = [
      RouterStatusEntryV3.create({'r': r_line % 'kvy2dIpA5giOIvurlDqy3XQ+qBg=', 's': ' '}),
      RouterStatusEntryV3.create({'r': r_line % 'aHH2gjULqTGDjA7B5KIwRNrganM=', 's': ' '}),
      RouterStatusEntryV3.create({'r': r_line % '4rsTqi9pYM2Tq+UleoJWh/OXPGI=', 's': ' '}),
      RouterStatusEntryV3.create({'r': r_line % 'VGxU4qidiOB5TQSuy/Gsisnagd4='}),
      RouterStatusEntryV3.create({'r': r_line % '3K7D0GncOarkPRPIrzG1ZF4F7WE='}),
    ])

    maatuska_consensus = NetworkStatusDocumentV3.create(routers = [
      RouterStatusEntryV3.create({'r': r_line % 'kvy2dIpA5giOIvurlDqy3XQ+qBg='}),
      RouterStatusEntryV3.create({'r': r_line % 'aHH2gjULqTGDjA7B5KIwRNrganM='}),
      RouterStatusEntryV3.create({'r': r_line % '4rsTqi9pYM2Tq+UleoJWh/OXPGI='}),
      RouterStatusEntryV3.create({'r': r_line % 'VGxU4qidiOB5TQSuy/Gsisnagd4=', 's': ' '}),
      RouterStatusEntryV3.create({'r': r_line % '3K7D0GncOarkPRPIrzG1ZF4F7WE=', 's': ' '}),
    ])

    query_mock().run.side_effect = [[moria1_consensus], [maatuska_consensus]]

    import compare_flags

    self.assertEqual(EXPECTED_COMPARE_FLAGS, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = io.StringIO)
  def test_create_descriptor(self, stdout_mock):
    import create_descriptor

    # First line is randomized, for example...
    #
    #   Unnamed566296572314 (226.149.46.74:9001)
    #   demo (127.0.0.1:80)

    lines = stdout_mock.getvalue().splitlines()

    self.assertTrue(lines[0].startswith('Unnamed'))
    self.assertEqual('demo (127.0.0.1:80)', lines[1])

  @patch('sys.stdout', new_callable = io.StringIO)
  def test_create_descriptor_content(self, stdout_mock):
    import create_descriptor_content

    self.assertTrue(stdout_mock.getvalue().startswith('router demo 127.0.0.1 80 0 0\npublish'))

  @patch('stem.descriptor.remote.DescriptorDownloader')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_current_descriptors(self, stdout_mock, downloader_mock):
    downloader_mock().get_consensus.return_value = [RouterStatusEntryV2.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    })]

    import current_descriptors

    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_custom_path_selection(self, stdout_mock, from_port_mock):
    original_modules = dict(sys.modules)

    try:
      # pycurl mocked out so its query method returns an empty string

      sys.modules['pycurl'] = Mock()

      controller = from_port_mock().__enter__()
      controller.get_network_statuses.return_value = [RouterStatusEntryV2.create({
        'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
      })]

      import custom_path_selection

      self.assertEqual("A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB => Request didn't have the right content\n", stdout_mock.getvalue())
    finally:
      sys.modules = original_modules

  @patch('stem.descriptor.remote.DescriptorDownloader')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_descriptor_from_orport(self, stdout_mock, downloader_mock):
    downloader_mock().get_consensus.return_value = [
      RouterStatusEntryV3.create({
        'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
      })
    ]

    import descriptor_from_orport

    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_descriptor_from_tor_control_socket(self, stdout_mock, from_port_mock):
    controller = from_port_mock().__enter__()
    controller.get_network_statuses.return_value = [RouterStatusEntryV2.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    })]

    import descriptor_from_tor_control_socket

    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('stem.descriptor.parse_file')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_descriptor_from_tor_data_directory(self, stdout_mock, parse_file_mock):
    parse_file_mock.return_value = [RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    })]

    import descriptor_from_tor_data_directory

    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('sys.exit', Mock())
  def test_download_descriptor(self):
    import download_descriptor

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      with patch('stem.descriptor.remote.get_server_descriptors', _download_of([])):
        download_descriptor.main(['--help'])
        self.assertTrue(stdout_mock.getvalue().startswith("Downloads a descriptor through Tor's ORPort"))

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      download_descriptor.main(['--type', 'kaboom'])
      self.assertEqual(EXPECTED_DOWNLOAD_DESCRIPTOR_UNKNOWN_TYPE, stdout_mock.getvalue())

    server_desc = RelayDescriptor.create({'router': 'caerSidi 71.35.133.197 9001 0 0'})

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      with patch('stem.descriptor.remote.get_server_descriptors', _download_of(server_desc)):
        download_descriptor.main(['--dirport', '1.2.3.4:443'])
        self.assertTrue(stdout_mock.getvalue().startswith(EXPECTED_DOWNLOAD_DESCRIPTOR_PREFIX))

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_ephemeral_hidden_services(self, stdout_mock, from_port_mock):
    original_modules = dict(sys.modules)

    try:
      sys.modules['flask'] = Mock()

      controller = from_port_mock().__enter__()
      hidden_service = controller.create_ephemeral_hidden_service()
      hidden_service.service_id = 'my-service'

      import ephemeral_hidden_services

      self.assertEqual(EXPECTED_EPHEMEREAL_HIDDEN_SERVICES, stdout_mock.getvalue())
    finally:
      sys.modules = original_modules

  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_event_listening(self, from_port_mock):
    # This is a lengthy example that's mostly curses. This is just a surface
    # level test to check for syntax issues and such.

    original_modules = dict(sys.modules)

    try:
      sys.modules['curses'] = Mock()

      import event_listening

      event_listening.main()
      event_listening._render_graph(Mock(), [(0, 0)] * event_listening.GRAPH_WIDTH)
    finally:
      sys.modules = original_modules

  @unittest.expectedFailure
  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_exit_used(self, stdout_mock, from_port_mock):
    path_1 = ('9EA317EECA56BDF30CAEB208A253FB456EDAB1A0', 'bolobolo1')
    path_2 = ('00C2C2A16AEDB51D5E5FB7D6168FC66B343D822F', 'ph3x')
    path_3 = ('A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7', 'chaoscomputerclub19')

    event = ControlMessage.from_str('650 STREAM 15 SUCCEEDED 3 64.15.112.44:80', 'EVENT', normalize = True)
    r_line = '%s pZ4efH6u4IPXVu4f9uwxyj2GUdc= oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 31.172.30.2 443 0'

    controller = from_port_mock().__enter__()
    controller.get_circuit.return_value = _make_circ_event(1, path_1, path_2, path_3)
    controller.get_network_status.return_value = RouterStatusEntryV3.create({'r': r_line % path_3[1]})
    controller.get_info.return_value = 'unknown'

    import exit_used

    with patch('builtins.input', Mock(side_effect = functools.partial(exit_used.stream_event, controller, event))):
      exit_used.main()

    self.assertEqual(EXPECTED_EXIT_USED, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = io.StringIO)
  def test_fibonacci_multiprocessing(self, stdout_mock):
    # This example intentionally takes a long time (~11 seconds), so replacing
    # the work it does with a no-op.

    with patch('fibonacci_multiprocessing.fibonacci', Mock(return_value = 5)):
      import fibonacci_multiprocessing

      fibonacci_multiprocessing.main()
      self.assertEqual('took 0.0 seconds\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = io.StringIO)
  def test_fibonacci_threaded(self, stdout_mock):
    with patch('fibonacci_threaded.fibonacci', Mock(return_value = 5)):
      import fibonacci_threaded

      fibonacci_threaded.main()
      self.assertEqual('took 0.0 seconds\n', stdout_mock.getvalue())

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_get_hidden_service_descriptor(self, stdout_mock, from_port_mock):
    controller = from_port_mock().__enter__()
    controller.get_hidden_service_descriptor.return_value = HiddenServiceDescriptorV2.create()

    import get_hidden_service_descriptor

    self.assertTrue(stdout_mock.getvalue().startswith('rendezvous-service-descriptor '))

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_hello_world(self, stdout_mock, from_port_mock):
    controller = from_port_mock().__enter__()
    controller.get_info.side_effect = lambda arg: {
      'traffic/read': '33406',
      'traffic/written': '29649',
    }[arg]

    import hello_world

    self.assertEqual('My Tor relay has read 33406 bytes and written 29649.\n', stdout_mock.getvalue())

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_introduction_points(self, stdout_mock, from_port_mock):
    controller = from_port_mock().__enter__()
    controller.get_hidden_service_descriptor.return_value = next(stem.descriptor.parse_file(os.path.join(DESC_DIR, 'hidden_service_duckduckgo')))

    import introduction_points

    self.assertEqual(EXPECTED_INTRODUCTION_POINTS, stdout_mock.getvalue())

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_list_circuits(self, stdout_mock, from_port_mock):
    path_1 = ('B1FA7D51B8B6F0CB585D944F450E7C06EDE7E44C', 'ByTORAndTheSnowDog')
    path_2 = ('0DD9935C5E939CFA1E07B8DDA6D91C1A2A9D9338', 'afo02')
    path_3 = ('DB3B1CFBD3E4D97B84B548ADD5B9A31451EEC4CC', 'edwardsnowden3')
    path_4 = ('EC01CB4766BADC1611678555CE793F2A7EB2D723', 'sprockets')
    path_5 = ('9EA317EECA56BDF30CAEB208A253FB456EDAB1A0', 'bolobolo1')
    path_6 = ('00C2C2A16AEDB51D5E5FB7D6168FC66B343D822F', 'ph3x')
    path_7 = ('65242C91BFF30F165DA4D132C81A9EBA94B71D62', 'torexit16')

    circuit_4 = _make_circ_event(4, path_1, path_2, path_3)
    circuit_6 = _make_circ_event(6, path_1, path_4, path_5)
    circuit_10 = _make_circ_event(10, path_1, path_6, path_7)

    controller = from_port_mock().__enter__()
    controller.get_circuits.return_value = [circuit_4, circuit_6, circuit_10]

    r_line = 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 %s 9001 0'

    controller.get_network_status.side_effect = lambda fingerprint, *args: {
      path_1[0]: RouterStatusEntryV3.create({'r': r_line % '173.209.180.61'}),
      path_2[0]: RouterStatusEntryV3.create({'r': r_line % '87.238.194.176'}),
      path_3[0]: RouterStatusEntryV3.create({'r': r_line % '109.163.234.10'}),
      path_4[0]: RouterStatusEntryV3.create({'r': r_line % '46.165.197.96'}),
      path_5[0]: RouterStatusEntryV3.create({'r': r_line % '96.47.226.20'}),
      path_6[0]: RouterStatusEntryV3.create({'r': r_line % '86.59.119.83'}),
      path_7[0]: RouterStatusEntryV3.create({'r': r_line % '176.67.169.171'}),
    }[fingerprint]

    import list_circuits

    self.assertEqual(EXPECTED_LIST_CIRCUITS, stdout_mock.getvalue())

  @patch('stem.manual.Manual.from_remote', Mock(return_value = stem.manual.Manual.from_cache()))
  @patch('stem.util.term.format', Mock(side_effect = lambda msg, *args: msg))
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_manual_config_options(self, stdout_mock):
    with patch('builtins.input', Mock(side_effect = ['IPv6Exit', KeyboardInterrupt()])):
      import manual_config_options

    self.assertEqual(EXPECTED_MANUAL_CONFIG_OPTIONS, stdout_mock.getvalue())

  @patch('stem.descriptor.remote.DescriptorDownloader')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_outdated_relays(self, stdout_mock, downloader_mock):
    downloader_mock().get_server_descriptors.return_value = [
      RelayDescriptor.create({'platform': 'node-Tor 0.2.3.0 on Linux x86_64'}),
      RelayDescriptor.create({'platform': 'node-Tor 0.1.0 on Linux x86_64'}),
      RelayDescriptor.create({'opt': 'contact Random Person admin@gtr-10.de', 'platform': 'node-Tor 0.2.3.0 on Linux x86_64'}),
      RelayDescriptor.create({'opt': 'contact Sambuddha Basu', 'platform': 'node-Tor 0.1.0 on Linux x86_64'}),
    ]

    import outdated_relays

    self.assertEqual(EXPECTED_OUTDATED_RELAYS, stdout_mock.getvalue())

  @patch('stem.descriptor.remote.DescriptorDownloader')
  def test_persisting_a_consensus(self, downloader_mock):
    consensus = NetworkStatusDocumentV3.create(routers = (RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    }),))

    downloader_mock().get_consensus = _download_of(consensus)

    try:
      import persisting_a_consensus

      with open('/tmp/descriptor_dump') as output_file:
        self.assertEqual(str(consensus), output_file.read())
    finally:
      if os.path.exists('/tmp/descriptor_dump'):
        os.remove('/tmp/descriptor_dump')

  @patch('stem.descriptor.parse_file')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_persisting_a_consensus_with_parse_file(self, stdout_mock, parse_file_mock):
    consensus = NetworkStatusDocumentV3.create(routers = (RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    }),))

    parse_file_mock.return_value = iter([consensus])

    import persisting_a_consensus_with_parse_file

    self.assertEqual(EXPECTED_PERSISTING_A_CONSENSUS, stdout_mock.getvalue())

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_queue_listener(self, stdout_mock, from_port_mock):
    bw_event = ControlMessage.from_str('650 BW 15 25', 'EVENT', normalize = True)

    controller = from_port_mock().__enter__()
    controller.add_event_listener.side_effect = lambda handler, event_type: handler(bw_event)

    with patch('time.time', Mock(side_effect = [1, 1, 10])):
      import queue_listener

    self.assertEqual('I got a BW event for 15 bytes downloaded and 25 bytes uploaded\n', stdout_mock.getvalue())

  @patch('stem.descriptor.parse_file')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_read_with_parse_file(self, stdout_mock, parse_file_mock):
    parse_file_mock.return_value = [RelayDescriptor.create({'fingerprint': '4F0C 867D F0EF 6816 0568 C826 838F 482C EA7C FE44'})]

    import read_with_parse_file

    self.assertEqual('4F0C867DF0EF68160568C826838F482CEA7CFE44\n', stdout_mock.getvalue())

  @patch('sys.exit', Mock())
  @patch('time.time', Mock(return_value = 100))
  @patch('stem.util.system.start_time', Mock(return_value = 50))
  @patch('stem.util.connection.get_connections')
  @patch('stem.connection.connect')
  def test_relay_connections(self, connect_mock, get_connections_mock):
    import relay_connections

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      connect_mock.return_value = None

      relay_connections.main(['--help'])
      self.assertEqual(EXPECTED_RELAY_CONNECTIONS_HELP, stdout_mock.getvalue())

    with patch('sys.stdout', new_callable = io.StringIO) as stdout_mock:
      consensus_desc = RouterStatusEntryV2.create({
        'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
        's': 'Fast Stable',
      })

      controller = Mock()
      controller.get_pid.return_value = 123
      controller.get_version.return_value = stem.version.Version('1.2.3.4')
      controller.get_exit_policy.return_value = ExitPolicy('reject *:*')
      controller.get_network_status.return_value = consensus_desc
      controller.get_network_statuses.return_value = [consensus_desc]

      controller.get_ports.side_effect = lambda port_type, default_val: {
        Listener.OR: [4369],
        Listener.DIR: [443],
        Listener.CONTROL: [9100],
      }.get(port_type, default_val)

      connect_mock.return_value = controller

      get_connections_mock.return_value = [
        Connection('17.17.17.17', 4369, '34.34.34.34', 8738, 'tcp', False),
        Connection('18.18.18.18', 443, '35.35.35.35', 4281, 'tcp', False),
        Connection('19.19.19.19', 443, '36.36.36.36', 2814, 'tcp', False),
        Connection('20.20.20.20', 9100, '37.37.37.37', 2814, 'tcp', False),
        Connection('21.21.21.21', 80, '38.38.38.38', 8142, 'tcp', False),
      ]

      relay_connections.main([])
      self.assertEqual(EXPECTED_RELAY_CONNECTIONS, stdout_mock.getvalue())

  @patch('builtins.input', Mock())
  @patch('os.path.expanduser', Mock(return_value = '/tmp/stem_hs_test'))
  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_resuming_ephemeral_hidden_service(self, stdout_mock, from_port_mock):
    hs_response = '250-ServiceID=gfzprpioee3hoppz\n250-PrivateKey=RSA1024:MIICXgIB\n250 OK'

    controller = from_port_mock().__enter__()
    controller.create_ephemeral_hidden_service.return_value = ControlMessage.from_str(hs_response, 'ADD_ONION', normalize = True)

    try:
      import resuming_ephemeral_hidden_service

      with open('/tmp/stem_hs_test') as key_file:
        self.assertEqual('RSA1024:MIICXgIB', key_file.read())

      self.assertEqual('Started a new hidden service with the address of gfzprpioee3hoppz.onion\n', stdout_mock.getvalue())
    finally:
      if os.path.exists('/tmp/stem_hs_test'):
        os.remove('/tmp/stem_hs_test')

  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('shutil.rmtree')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_running_hidden_service(self, stdout_mock, rmtree_mock, from_port_mock):
    original_modules = dict(sys.modules)

    try:
      flask_mock = Mock()

      hidden_service_data = Mock()
      hidden_service_data.hostname = 'uxiuaxejc3sxrb6i.onion'

      controller = from_port_mock().__enter__()
      controller.get_conf.return_value = '/home/atagar/.tor'
      controller.create_hidden_service.return_value = hidden_service_data

      sys.modules['flask'] = flask_mock

      import running_hidden_service

      controller.get_conf.assert_called_once_with('DataDirectory', '/tmp')
      controller.create_hidden_service.assert_called_once_with('/home/atagar/.tor/hello_world', 80, target_port = 5000)
      rmtree_mock.assert_called_once_with('/home/atagar/.tor/hello_world')

      self.assertEqual(EXPECTED_RUNNING_HIDDEN_SERVICE, stdout_mock.getvalue())
    finally:
      sys.modules = original_modules

  def test_saving_and_loading_descriptors(self):
    server_desc = RelayDescriptor.create({'router': 'caerSidi 71.35.133.197 9001 0 0'})

    with patch('stem.descriptor.remote.get_server_descriptors', _download_of(server_desc)):
      try:
        import saving_and_loading_descriptors

        with open('/tmp/descriptor_dump') as descriptor_file:
          self.assertTrue(descriptor_file.read().startswith('router caerSidi 71.35.133.197'))
      finally:
        if os.path.exists('/tmp/descriptor_dump'):
          os.remove('/tmp/descriptor_dump')

  @patch('time.sleep')
  @patch('time.time', Mock(return_value = 123))
  @patch('stem.control.Controller.authenticate', Mock())
  @patch('stem.control.Controller.is_alive', Mock(return_value = True))
  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_slow_listener(self, stdout_mock, from_port_mock, sleep_mock):
    controller = Controller(stem.socket.ControlSocket())
    from_port_mock.return_value = controller

    # emits a BW event when the example runs time.sleep() at the end, but *not*
    # within the listener

    bw_event = ControlMessage.from_str('650 BW 15 25', 'EVENT', normalize = True)
    sleep_mock.side_effect = lambda duration: controller._handle_event(bw_event) if duration == 10 else None

    import slow_listener

    self.assertEqual("processing a BW event that's 0.0 seconds old (0 more events are waiting)\n", stdout_mock.getvalue())

  @patch('stem.descriptor.remote.DescriptorDownloader')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_tor_descriptors(self, stdout_mock, downloader_mock):
    exit_descriptor = RelayDescriptor.content({'router': 'speedyexit 149.255.97.109 9001 0 0'}).replace(b'reject *:*', b'accept *:*')
    exit_descriptor = RelayDescriptor(exit_descriptor)

    downloader_mock().get_server_descriptors().run.return_value = [
      exit_descriptor,
      RelayDescriptor.create(),  # non-exit
      exit_descriptor,
      exit_descriptor,
    ]

    import tor_descriptors

    self.assertEqual(EXPECTED_TOR_DESCRIPTORS, stdout_mock.getvalue())

  @patch('stem.util.connection.system_resolvers', Mock(return_value = [Resolver.NETSTAT]))
  @patch('stem.util.system.pid_by_name', Mock(return_value = [12345]))
  @patch('stem.util.connection.get_connections')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_utilities(self, stdout_mock, get_connections_mock):
    get_connections_mock.return_value = [
      Connection('17.17.17.17', 4369, '34.34.34.34', 8738, 'tcp', False),
      Connection('18.18.18.18', 443, '35.35.35.35', 4281, 'tcp', False),
    ]

    import utilities

    self.assertEqual(EXPECTED_UTILITIES, stdout_mock.getvalue())

  @patch('stem.descriptor.parse_file')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_validate_descriptor_content(self, stdout_mock, parse_file_mock):
    parse_file_mock.return_value = [RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    })]

    import validate_descriptor_content

    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('stem.descriptor.remote.DescriptorDownloader.query')
  @patch('stem.directory.Authority.from_cache')
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_votes_by_bandwidth_authorities(self, stdout_mock, authorities_mock, query_mock):
    authorities_mock().values.return_value = [
      DIRECTORY_AUTHORITIES['gabelmoo'],
      DIRECTORY_AUTHORITIES['moria1'],
      DIRECTORY_AUTHORITIES['maatuska'],
    ]

    entry_with_measurement = RouterStatusEntryV3.create({'w': 'Bandwidth=1 Measured=1'})
    entry_without_measurement = RouterStatusEntryV3.create()

    query1 = Mock()
    query1.download_url = 'http://131.188.40.189:80/tor/status-vote/current/authority'
    query1.run.return_value = [entry_with_measurement] * 5935 + [entry_without_measurement] * 1332

    query2 = Mock()
    query2.download_url = 'http://128.31.0.39:9131/tor/status-vote/current/authority'
    query2.run.return_value = [entry_with_measurement] * 6647 + [entry_without_measurement] * 625

    query3 = Mock()
    query3.download_url = 'http://171.25.193.9:443/tor/status-vote/current/authority'
    query3.run.return_value = [entry_with_measurement] * 6313 + [entry_without_measurement] * 1112

    query_mock.side_effect = [query1, query2, query3]

    import votes_by_bandwidth_authorities

    self.assertEqual(EXPECTED_VOTES_BY_BANDWIDTH_AUTHORITIES, stdout_mock.getvalue())

  @patch('builtins.input', Mock(return_value = 'hel'))
  @patch('builtins.open', mock_open(read_data = 'hello\nnope\nhellena'))
  @patch('stem.util.term.format', Mock(side_effect = lambda msg, *args: msg))
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_words_with(self, stdout_mock):
    import words_with

    words_with.main()

    self.assertEqual(EXPECTED_WORDS_WITH.rstrip(), stdout_mock.getvalue().rstrip())
