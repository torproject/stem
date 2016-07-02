"""
Tests for the examples given in stem's tutorial.
"""

import itertools
import os
import unittest

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

import stem.response
import stem.descriptor.remote
import stem.prereq

import test.runner

from stem.control import Controller
from stem.util import str_type
from stem.descriptor.remote import DIRECTORY_AUTHORITIES

from test import mocking
from test.unit import exec_documentation_example
from test.mocking import (
  get_relay_server_descriptor,
  get_router_status_entry_v3,
  ROUTER_STATUS_ENTRY_V3_HEADER,
  get_network_status_document_v3,
)

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

OPEN_FUNCTION = open  # make a reference so mocking open() won't mess with us

CIRC_CONTENT = '650 CIRC %d %s \
%s \
PURPOSE=%s'

PATH_CONTENT = '$%s=%s,$%s=%s,$%s=%s'

LIST_CIRCUITS_OUTPUT = str_type("""\

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
""")

EXIT_USED_OUTPUT = str_type("""\
Tracking requests for tor exits. Press 'enter' to end.

Exit relay for our connection to 64.15.112.44:80
  address: 31.172.30.2:443
  fingerprint: A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7
  nickname: chaoscomputerclub19
  locale: unknown

""")

OUTDATED_RELAYS_OUTPUT = str_type("""\
Checking for outdated relays...

  0.1.0           Sambuddha Basu

2 outdated relays found, 1 had contact information
""")

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
  controller_event = mocking.get_message(content)
  stem.response.convert('EVENT', controller_event)
  return controller_event


def _get_circ_event(id, status, hop1, hop2, hop3, purpose):
  path = PATH_CONTENT % (hop1[0], hop1[1], hop2[0], hop2[1], hop3[0], hop3[1])
  content = CIRC_CONTENT % (id, status, path, purpose)
  return _get_event(content)


def _get_router_status(address = None, port = None, nickname = None, fingerprint_base64 = None, s_line = None):
  r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1]

  if address:
    r_line = r_line.replace('71.35.150.29', address)

  if port:
    r_line = r_line.replace('9001', port)

  if nickname:
    r_line = r_line.replace('caerSidi', nickname)

  if fingerprint_base64:
    r_line = r_line.replace('p1aag7VwarGxqctS7/fS0y5FU+s', fingerprint_base64)

  if s_line:
    return get_router_status_entry_v3({'r': r_line, 's': s_line})
  else:
    return get_router_status_entry_v3({'r': r_line})


class TestTutorialExamples(unittest.TestCase):
  def assert_equal_unordered(self, expected, actual):
    if stem.prereq.is_python_3():
      self.assertCountEqual(expected.splitlines(), actual.splitlines())
    else:
      self.assertItemsEqual(expected.splitlines(), actual.splitlines())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_list_circuits(self, from_port_mock, stdout_mock):
    path_1 = ('B1FA7D51B8B6F0CB585D944F450E7C06EDE7E44C', 'ByTORAndTheSnowDog')
    path_2 = ('0DD9935C5E939CFA1E07B8DDA6D91C1A2A9D9338', 'afo02')
    path_3 = ('DB3B1CFBD3E4D97B84B548ADD5B9A31451EEC4CC', 'edwardsnowden3')
    path_4 = ('EC01CB4766BADC1611678555CE793F2A7EB2D723', 'sprockets')
    path_5 = ('9EA317EECA56BDF30CAEB208A253FB456EDAB1A0', 'bolobolo1')
    path_6 = ('00C2C2A16AEDB51D5E5FB7D6168FC66B343D822F', 'ph3x')
    path_7 = ('65242C91BFF30F165DA4D132C81A9EBA94B71D62', 'torexit16')

    circuit_4 = _get_circ_event(4, 'BUILT', path_1, path_2, path_3, 'GENERAL')
    circuit_6 = _get_circ_event(6, 'BUILT', path_1, path_4, path_5, 'GENERAL')
    circuit_10 = _get_circ_event(10, 'BUILT', path_1, path_6, path_7, 'GENERAL')

    controller = from_port_mock().__enter__()
    controller.get_circuits.return_value = [circuit_4, circuit_6, circuit_10]

    controller.get_network_status.side_effect = lambda fingerprint, *args: {
      path_1[0]: _get_router_status('173.209.180.61'),
      path_2[0]: _get_router_status('87.238.194.176'),
      path_3[0]: _get_router_status('109.163.234.10'),
      path_4[0]: _get_router_status('46.165.197.96'),
      path_5[0]: _get_router_status('96.47.226.20'),
      path_6[0]: _get_router_status('86.59.119.83'),
      path_7[0]: _get_router_status('176.67.169.171')
    }[fingerprint]

    exec_documentation_example('list_circuits.py')
    self.assert_equal_unordered(LIST_CIRCUITS_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_exit_used(self, from_port_mock, stdout_mock):
    def tutorial_example(mock_event):
      import functools

      from stem import StreamStatus
      from stem.control import EventType, Controller

      def main():
        print("Tracking requests for tor exits. Press 'enter' to end.\n")

        with Controller.from_port() as controller:
          controller.authenticate()

          stream_listener = functools.partial(stream_event, controller)
          controller.add_event_listener(stream_listener, EventType.STREAM)

          stream_event(controller, mock_event)  # simulate an event during the raw_input()

      def stream_event(controller, event):
        if event.status == StreamStatus.SUCCEEDED and event.circ_id:
          circ = controller.get_circuit(event.circ_id)

          exit_fingerprint = circ.path[-1][0]
          exit_relay = controller.get_network_status(exit_fingerprint)

          print('Exit relay for our connection to %s' % (event.target))
          print('  address: %s:%i' % (exit_relay.address, exit_relay.or_port))
          print('  fingerprint: %s' % exit_relay.fingerprint)
          print('  nickname: %s' % exit_relay.nickname)
          print('  locale: %s\n' % controller.get_info('ip-to-country/%s' % exit_relay.address, 'unknown'))

      main()

    path_1 = ('9EA317EECA56BDF30CAEB208A253FB456EDAB1A0', 'bolobolo1')
    path_2 = ('00C2C2A16AEDB51D5E5FB7D6168FC66B343D822F', 'ph3x')
    path_3 = ('A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7', 'chaoscomputerclub19')
    circuit = _get_circ_event(1, 'BUILT', path_1, path_2, path_3, 'GENERAL')

    event_content = '650 STREAM 15 SUCCEEDED 3 64.15.112.44:80'
    event = _get_event(event_content)

    controller = from_port_mock().__enter__()
    controller.get_circuit.return_value = circuit
    controller.get_network_status.return_value = _get_router_status('31.172.30.2', '443', path_3[1], 'pZ4efH6u4IPXVu4f9uwxyj2GUdc=')
    controller.get_info.return_value = 'unknown'

    tutorial_example(event)
    self.assert_equal_unordered(EXIT_USED_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.remote.DescriptorDownloader')
  def test_outdated_relays(self, downloader_mock, stdout_mock):
    downloader_mock().get_server_descriptors.return_value = [
      get_relay_server_descriptor({'platform': 'node-Tor 0.2.3.0 on Linux x86_64'}),
      get_relay_server_descriptor({'platform': 'node-Tor 0.1.0 on Linux x86_64'}),
      get_relay_server_descriptor({'opt': 'contact Random Person admin@gtr-10.de', 'platform': 'node-Tor 0.2.3.0 on Linux x86_64'}),
      get_relay_server_descriptor({'opt': 'contact Sambuddha Basu', 'platform': 'node-Tor 0.1.0 on Linux x86_64'}),
    ]

    exec_documentation_example('outdated_relays.py')

    self.assert_equal_unordered(OUTDATED_RELAYS_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.remote.Query')
  @patch('stem.descriptor.remote.get_authorities')
  def test_compare_flags(self, get_authorities_mock, query_mock, stdout_mock):
    if stem.prereq._is_python_26():
      # example imports OrderedDict from collections which doesn't work under
      # python 2.6

      test.runner.skip(self, "(example doesn't support python 2.6)")
      return

    get_authorities_mock().items.return_value = [('moria1', DIRECTORY_AUTHORITIES['moria1']), ('maatuska', DIRECTORY_AUTHORITIES['maatuska'])]

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
      [get_network_status_document_v3(routers = (entry[0], entry[1], entry[2], entry[3], entry[4]))],
      [get_network_status_document_v3(routers = (entry[5], entry[6], entry[7], entry[8], entry[9]))],
    ]

    exec_documentation_example('compare_flags.py')

    self.assert_equal_unordered(COMPARE_FLAGS_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.remote.get_authorities')
  @patch('stem.descriptor.remote.DescriptorDownloader.query')
  def test_votes_by_bandwidth_authorities(self, query_mock, get_authorities_mock, stdout_mock):
    directory_values = [
      DIRECTORY_AUTHORITIES['gabelmoo'],
      DIRECTORY_AUTHORITIES['moria1'],
      DIRECTORY_AUTHORITIES['maatuska'],
    ]

    directory_values[0].address = '131.188.40.189'
    get_authorities_mock().values.return_value = directory_values

    entry_with_measurement = get_router_status_entry_v3({'w': 'Bandwidth=1 Measured=1'})
    entry_without_measurement = get_router_status_entry_v3()

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
    self.assert_equal_unordered(VOTES_BY_BANDWIDTH_AUTHORITIES_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO)
  @patch('stem.descriptor.parse_file')
  @patch('%s.open' % __name__, create = True)
  @patch('stem.descriptor.remote.Query')
  def test_persisting_a_consensus(self, query_mock, open_mock, parse_file_mock, stdout_mock):
    def tutorial_example_2():
      from stem.descriptor import DocumentHandler, parse_file

      consensus = next(parse_file(
        '/tmp/descriptor_dump',
        descriptor_type = 'network-status-consensus-3 1.0',
        document_handler = DocumentHandler.DOCUMENT,
      ))

      for fingerprint, relay in consensus.routers.items():
        print('%s: %s' % (fingerprint, relay.nickname))

    network_status = get_network_status_document_v3(routers = (get_router_status_entry_v3(),))
    query_mock().run.return_value = [network_status]
    parse_file_mock.return_value = itertools.cycle([network_status])

    exec_documentation_example('persisting_a_consensus.py')
    exec_documentation_example('persisting_a_consensus_with_parse_file.py')

    self.assertEqual(PERSISTING_A_CONSENSUS_OUTPUT, stdout_mock.getvalue())

    if os.path.exists('/tmp/descriptor_dump'):
      os.remove('/tmp/descriptor_dump')
