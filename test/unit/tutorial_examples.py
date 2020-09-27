"""
Tests for the examples given in stem's tutorial.
"""

import io
import itertools
import os
import unittest

from unittest.mock import Mock, patch

from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.router_status_entry import RouterStatusEntryV3
from stem.descriptor.server_descriptor import RelayDescriptor
from stem.directory import DIRECTORY_AUTHORITIES
from stem.response import ControlMessage

from test.unit import exec_documentation_example

OPEN_FUNCTION = open  # make a reference so mocking open() won't mess with us

CIRC_CONTENT = '650 CIRC %d %s \
%s \
PURPOSE=%s'

PATH_CONTENT = '$%s=%s,$%s=%s,$%s=%s'

OUTDATED_RELAYS_OUTPUT = """\
Checking for outdated relays...

  0.1.0           Sambuddha Basu

2 outdated relays found, 1 had contact information
"""

COMPARE_FLAGS_OUTPUT = """\
maatuska has the Running flag but moria1 doesn't: E2BB13AA2F6960CD93ABE5257A825687F3973C62
moria1 has the Running flag but maatuska doesn't: 546C54E2A89D88E0794D04AECBF1AC8AC9DA81DE
maatuska has the Running flag but moria1 doesn't: 92FCB6748A40E6088E22FBAB943AB2DD743EA818
maatuska has the Running flag but moria1 doesn't: 6871F682350BA931838C0EC1E4A23044DAE06A73
moria1 has the Running flag but maatuska doesn't: DCAEC3D069DC39AAE43D13C8AF31B5645E05ED61
"""

VOTES_BY_BANDWIDTH_AUTHORITIES_OUTPUT = """\
Getting gabelmoo's vote from http://131.188.40.189:80/tor/status-vote/current/authority:
  5935 measured entries and 1332 unmeasured
Getting moria1's vote from http://128.31.0.39:9131/tor/status-vote/current/authority:
  6647 measured entries and 625 unmeasured
Getting maatuska's vote from http://171.25.193.9:443/tor/status-vote/current/authority:
  6313 measured entries and 1112 unmeasured
"""

PERSISTING_A_CONSENSUS_OUTPUT = """\
A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB: caerSidi
"""


def _get_event(content):
  return ControlMessage.from_str(content, 'EVENT', normalize = True)


def _get_circ_event(id, status, hop1, hop2, hop3, purpose):
  path = PATH_CONTENT % (hop1[0], hop1[1], hop2[0], hop2[1], hop3[0], hop3[1])
  content = CIRC_CONTENT % (id, status, path, purpose)
  return _get_event(content)


def _get_router_status(address = None, port = None, nickname = None, fingerprint_base64 = None, s_line = None):
  r_line = 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0'

  if address:
    r_line = r_line.replace('71.35.150.29', address)

  if port:
    r_line = r_line.replace('9001', port)

  if nickname:
    r_line = r_line.replace('caerSidi', nickname)

  if fingerprint_base64:
    r_line = r_line.replace('p1aag7VwarGxqctS7/fS0y5FU+s', fingerprint_base64)

  if s_line:
    return RouterStatusEntryV3.create({'r': r_line, 's': s_line})
  else:
    return RouterStatusEntryV3.create({'r': r_line})


class TestTutorialExamples(unittest.TestCase):
  @patch('sys.stdout', new_callable = io.StringIO)
  @patch('stem.descriptor.remote.DescriptorDownloader')
  def test_outdated_relays(self, downloader_mock, stdout_mock):
    downloader_mock().get_server_descriptors.return_value = [
      RelayDescriptor.create({'platform': 'node-Tor 0.2.3.0 on Linux x86_64'}),
      RelayDescriptor.create({'platform': 'node-Tor 0.1.0 on Linux x86_64'}),
      RelayDescriptor.create({'opt': 'contact Random Person admin@gtr-10.de', 'platform': 'node-Tor 0.2.3.0 on Linux x86_64'}),
      RelayDescriptor.create({'opt': 'contact Sambuddha Basu', 'platform': 'node-Tor 0.1.0 on Linux x86_64'}),
    ]

    exec_documentation_example('outdated_relays.py')

    self.assertCountEqual(OUTDATED_RELAYS_OUTPUT.splitlines(), stdout_mock.getvalue().splitlines())

  @patch('sys.stdout', new_callable = io.StringIO)
  @patch('stem.descriptor.remote.Query')
  @patch('stem.directory.Authority.from_cache')
  def test_compare_flags(self, authorities_mock, query_mock, stdout_mock):
    authorities_mock().items.return_value = [('moria1', DIRECTORY_AUTHORITIES['moria1']), ('maatuska', DIRECTORY_AUTHORITIES['maatuska'])]

    fingerprint = [
      ('92FCB6748A40E6088E22FBAB943AB2DD743EA818', 'kvy2dIpA5giOIvurlDqy3XQ+qBg='),
      ('6871F682350BA931838C0EC1E4A23044DAE06A73', 'aHH2gjULqTGDjA7B5KIwRNrganM='),
      ('E2BB13AA2F6960CD93ABE5257A825687F3973C62', '4rsTqi9pYM2Tq+UleoJWh/OXPGI='),
      ('546C54E2A89D88E0794D04AECBF1AC8AC9DA81DE', 'VGxU4qidiOB5TQSuy/Gsisnagd4='),
      ('DCAEC3D069DC39AAE43D13C8AF31B5645E05ED61', '3K7D0GncOarkPRPIrzG1ZF4F7WE='),
    ]

    entry = [
      # entries for moria1

      _get_router_status(fingerprint_base64 = fingerprint[0][1], s_line = ' '),
      _get_router_status(fingerprint_base64 = fingerprint[1][1], s_line = ' '),
      _get_router_status(fingerprint_base64 = fingerprint[2][1], s_line = ' '),
      _get_router_status(fingerprint_base64 = fingerprint[3][1]),
      _get_router_status(fingerprint_base64 = fingerprint[4][1]),

      # entries for maatuska

      _get_router_status(fingerprint_base64 = fingerprint[0][1]),
      _get_router_status(fingerprint_base64 = fingerprint[1][1]),
      _get_router_status(fingerprint_base64 = fingerprint[2][1]),
      _get_router_status(fingerprint_base64 = fingerprint[3][1], s_line = ' '),
      _get_router_status(fingerprint_base64 = fingerprint[4][1], s_line = ' '),
    ]

    query_mock().run.side_effect = [
      [NetworkStatusDocumentV3.create(routers = (entry[0], entry[1], entry[2], entry[3], entry[4]))],
      [NetworkStatusDocumentV3.create(routers = (entry[5], entry[6], entry[7], entry[8], entry[9]))],
    ]

    exec_documentation_example('compare_flags.py')

    self.assertCountEqual(COMPARE_FLAGS_OUTPUT.splitlines(), stdout_mock.getvalue().splitlines())

  @patch('sys.stdout', new_callable = io.StringIO)
  @patch('stem.directory.Authority.from_cache')
  @patch('stem.descriptor.remote.DescriptorDownloader.query')
  def test_votes_by_bandwidth_authorities(self, query_mock, authorities_mock, stdout_mock):
    directory_values = [
      DIRECTORY_AUTHORITIES['gabelmoo'],
      DIRECTORY_AUTHORITIES['moria1'],
      DIRECTORY_AUTHORITIES['maatuska'],
    ]

    directory_values[0].address = '131.188.40.189'
    authorities_mock().values.return_value = directory_values

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

    exec_documentation_example('votes_by_bandwidth_authorities.py')
    self.assertCountEqual(VOTES_BY_BANDWIDTH_AUTHORITIES_OUTPUT.splitlines(), stdout_mock.getvalue().splitlines())

  @patch('sys.stdout', new_callable = io.StringIO)
  @patch('stem.descriptor.parse_file')
  @patch('stem.descriptor.remote.Query')
  def test_persisting_a_consensus(self, query_mock, parse_file_mock, stdout_mock):
    def tutorial_example_2():
      from stem.descriptor import DocumentHandler, parse_file

      consensus = next(parse_file(
        '/tmp/descriptor_dump',
        descriptor_type = 'network-status-consensus-3 1.0',
        document_handler = DocumentHandler.DOCUMENT,
      ))

      for fingerprint, relay in consensus.routers.items():
        print('%s: %s' % (fingerprint, relay.nickname))

    network_status = NetworkStatusDocumentV3.create(routers = (RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    }),))

    query_mock().run.return_value = [network_status]
    parse_file_mock.return_value = itertools.cycle([network_status])

    exec_documentation_example('persisting_a_consensus.py')
    exec_documentation_example('persisting_a_consensus_with_parse_file.py')

    self.assertEqual(PERSISTING_A_CONSENSUS_OUTPUT, stdout_mock.getvalue())

    if os.path.exists('/tmp/descriptor_dump'):
      os.remove('/tmp/descriptor_dump')
