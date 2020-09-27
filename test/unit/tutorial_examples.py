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
from stem.directory import DIRECTORY_AUTHORITIES
from stem.response import ControlMessage

from test.unit import exec_documentation_example

OPEN_FUNCTION = open  # make a reference so mocking open() won't mess with us

CIRC_CONTENT = '650 CIRC %d %s \
%s \
PURPOSE=%s'

PATH_CONTENT = '$%s=%s,$%s=%s,$%s=%s'

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
