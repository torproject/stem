"""
Tests for the examples given in stem's tutorial.
"""

import StringIO
import unittest

import stem.response
import stem.descriptor.remote

from stem.control import Controller
from stem.descriptor.remote import DIRECTORY_AUTHORITIES
from test import mocking
from test.mocking import (
  get_relay_server_descriptor,
  get_router_status_entry_v3,
  ROUTER_STATUS_ENTRY_V3_HEADER,
  get_network_status_document_v3,
)

try:
  # added in python 3.3
  from unittest.mock import patch
except ImportError:
  from mock import patch

CIRC_CONTENT = '650 CIRC %d %s \
%s \
PURPOSE=%s'

PATH_CONTENT = '$%s=%s,$%s=%s,$%s=%s'

LIST_CIRCUITS_OUTPUT = """\

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

EXIT_USED_OUTPUT = """\
Tracking requests for tor exits. Press 'enter' to end.

Exit relay for our connection to 64.15.112.44:80
  address: 31.172.30.2:443
  fingerprint: A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7
  nickname: chaoscomputerclub19
  locale: unknown

"""

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
Getting gabelmoo's vote from http://212.112.245.170:80/tor/status-vote/current/authority:
  5935 measured entries and 1332 unmeasured
Getting tor26's vote from http://86.59.21.38:80/tor/status-vote/current/authority:
  5735 measured entries and 1690 unmeasured
Getting moria1's vote from http://128.31.0.39:9131/tor/status-vote/current/authority:
  6647 measured entries and 625 unmeasured
Getting maatuska's vote from http://171.25.193.9:443/tor/status-vote/current/authority:
  6313 measured entries and 1112 unmeasured
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
    content = get_router_status_entry_v3({'r': r_line, 's': s_line})
  else:
    content = get_router_status_entry_v3({'r': r_line})
  return content


class TestTutorialExamples(unittest.TestCase):
  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_list_circuits(self, from_port_mock, stdout_mock):
    def tutorial_example():
      from stem import CircStatus
      from stem.control import Controller

      with Controller.from_port(port = 9051) as controller:
        controller.authenticate()

        for circ in sorted(controller.get_circuits()):
          if circ.status != CircStatus.BUILT:
            continue

          print
          print "Circuit %s (%s)" % (circ.id, circ.purpose)

          for i, entry in enumerate(circ.path):
            div = '+' if (i == len(circ.path) - 1) else '|'
            fingerprint, nickname = entry

            desc = controller.get_network_status(fingerprint, None)
            address = desc.address if desc else 'unknown'

            print " %s- %s (%s, %s)" % (div, fingerprint, nickname, address)

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
      path_1[0]: _get_router_status("173.209.180.61"),
      path_2[0]: _get_router_status("87.238.194.176"),
      path_3[0]: _get_router_status("109.163.234.10"),
      path_4[0]: _get_router_status("46.165.197.96"),
      path_5[0]: _get_router_status("96.47.226.20"),
      path_6[0]: _get_router_status("86.59.119.83"),
      path_7[0]: _get_router_status("176.67.169.171")
    }[fingerprint]
    tutorial_example()
    self.assertEqual(LIST_CIRCUITS_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_exit_used(self, from_port_mock, stdout_mock):
    import functools

    from stem import StreamStatus
    from stem.control import EventType, Controller

    def main():
      print "Tracking requests for tor exits. Press 'enter' to end."
      print

      with Controller.from_port() as controller:
        controller.authenticate()

        stream_listener = functools.partial(stream_event, controller)
        controller.add_event_listener(stream_listener, EventType.STREAM)

        raw_input()

    def stream_event(controller, event):
      if event.status == StreamStatus.SUCCEEDED and event.circ_id:
        circ = controller.get_circuit(event.circ_id)

        exit_fingerprint = circ.path[-1][0]
        exit_relay = controller.get_network_status(exit_fingerprint)

        print "Exit relay for our connection to %s" % (event.target)
        print "  address: %s:%i" % (exit_relay.address, exit_relay.or_port)
        print "  fingerprint: %s" % exit_relay.fingerprint
        print "  nickname: %s" % exit_relay.nickname
        print "  locale: %s" % controller.get_info("ip-to-country/%s" % exit_relay.address, 'unknown')
        print

    path_1 = ('9EA317EECA56BDF30CAEB208A253FB456EDAB1A0', 'bolobolo1')
    path_2 = ('00C2C2A16AEDB51D5E5FB7D6168FC66B343D822F', 'ph3x')
    path_3 = ('A59E1E7C7EAEE083D756EE1FF6EC31CA3D8651D7', 'chaoscomputerclub19')
    circuit = _get_circ_event(1, 'BUILT', path_1, path_2, path_3, 'GENERAL')

    event_content = '650 STREAM 15 SUCCEEDED 3 64.15.112.44:80'
    event = _get_event(event_content)

    controller = from_port_mock().__enter()
    controller.get_circuit.return_value = circuit
    controller.get_network_status.return_value = _get_router_status("31.172.30.2", "443", path_3[1], "pZ4efH6u4IPXVu4f9uwxyj2GUdc=")
    controller.get_info.return_value = 'unknown'
    origin_raw_input = __builtins__['raw_input']
    __builtins__['raw_input'] = lambda: ""
    main()
    __builtins__['raw_input'] = origin_raw_input
    stream_event(controller, event)
    self.assertEqual(EXIT_USED_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.descriptor.remote.DescriptorDownloader')
  def test_outdated_relays(self, downloader_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor.remote import DescriptorDownloader
      from stem.version import Version

      downloader = DescriptorDownloader()
      count, with_contact = 0, 0

      print "Checking for outdated relays..."
      print

      for desc in downloader.get_server_descriptors():
        if desc.tor_version < Version('0.2.3.0'):
          count += 1

          if desc.contact:
            print '  %-15s %s' % (desc.tor_version, desc.contact.decode("utf-8", "replace"))
            with_contact += 1

      print
      print "%i outdated relays found, %i had contact information" % (count, with_contact)

    desc_1 = get_relay_server_descriptor({'platform': 'node-Tor 0.2.3.0 on Linux x86_64'})
    desc_2 = get_relay_server_descriptor({'platform': 'node-Tor 0.1.0 on Linux x86_64'})
    desc_3 = get_relay_server_descriptor({'opt': 'contact Random Person admin@gtr-10.de', 'platform': 'node-Tor 0.2.3.0 on Linux x86_64'})
    desc_4 = get_relay_server_descriptor({'opt': 'contact Sambuddha Basu', 'platform': 'node-Tor 0.1.0 on Linux x86_64'})
    downloader_mock().get_server_descriptors.return_value = [desc_1, desc_2, desc_3, desc_4]
    tutorial_example()
    self.assertEqual(OUTDATED_RELAYS_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.descriptor.remote.Query')
  @patch('stem.descriptor.remote.get_authorities')
  def test_compare_flags(self, get_authorities_mock, query_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor import DocumentHandler, remote

      # Query all authority votes asynchronously.

      downloader = remote.DescriptorDownloader(document_handler = DocumentHandler.DOCUMENT)
      queries = {}

      for name, authority in remote.get_authorities().items():
        if authority.v3ident is None:
          continue  # authority doens't vote if it lacks a v3ident

        queries[name] = downloader.get_vote(authority)

      # Wait for the votes to finish being downloaded, this produces a dictionary of
      # authority nicknames to their vote.

      votes = dict((name, query.run()[0]) for (name, query) in queries.items())

      # Get a superset of all the fingerprints in all the votes.

      all_fingerprints = set()

      for vote in votes.values():
        all_fingerprints.update(vote.routers.keys())

      # Finally, compare moria1's votes to maatuska.

      for fingerprint in all_fingerprints:
        moria1_vote = votes['moria1'].routers.get(fingerprint)
        maatuska_vote = votes['maatuska'].routers.get(fingerprint)

        if not moria1_vote and not maatuska_vote:
          print "both moria1 and maatuska haven't voted about %s" % fingerprint
        elif not moria1_vote:
          print "moria1 hasn't voted about %s" % fingerprint
        elif not maatuska_vote:
          print "maatuska hasn't voted about %s" % fingerprint
        elif 'Running' in moria1_vote.flags and 'Running' not in maatuska_vote.flags:
          print "moria1 has the Running flag but maatuska doesn't: %s" % fingerprint
        elif 'Running' in maatuska_vote.flags and 'Running' not in moria1_vote.flags:
          print "maatuska has the Running flag but moria1 doesn't: %s" % fingerprint

    get_authorities_mock().items.return_value = [('moria1', DIRECTORY_AUTHORITIES['moria1']), ('maatuska', DIRECTORY_AUTHORITIES['maatuska'])]
    fingerprint = []
    fingerprint.append(('92FCB6748A40E6088E22FBAB943AB2DD743EA818', 'kvy2dIpA5giOIvurlDqy3XQ+qBg='))
    fingerprint.append(('6871F682350BA931838C0EC1E4A23044DAE06A73', 'aHH2gjULqTGDjA7B5KIwRNrganM='))
    fingerprint.append(('E2BB13AA2F6960CD93ABE5257A825687F3973C62', '4rsTqi9pYM2Tq+UleoJWh/OXPGI='))
    fingerprint.append(('546C54E2A89D88E0794D04AECBF1AC8AC9DA81DE', 'VGxU4qidiOB5TQSuy/Gsisnagd4='))
    fingerprint.append(('DCAEC3D069DC39AAE43D13C8AF31B5645E05ED61', '3K7D0GncOarkPRPIrzG1ZF4F7WE='))
    entry = []
    # Entries for moria1.
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[0][1], s_line = ' '))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[1][1], s_line = ' '))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[2][1], s_line = ' '))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[3][1]))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[4][1]))
    # Entries for maatuska.
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[0][1]))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[1][1]))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[2][1]))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[3][1], s_line = ' '))
    entry.append(_get_router_status(fingerprint_base64 = fingerprint[4][1], s_line = ' '))
    network_status = []
    network_status.append(get_network_status_document_v3(routers = (entry[0], entry[1], entry[2], entry[3], entry[4],)))
    network_status.append(get_network_status_document_v3(routers = (entry[5], entry[6], entry[7], entry[8], entry[9],)))
    query_mock().run.side_effect = [[network_status[0]], [network_status[1]]]
    tutorial_example()
    self.assertEqual(COMPARE_FLAGS_OUTPUT, stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.descriptor.remote.get_authorities')
  @patch('stem.descriptor.remote.Query.run')
  def test_votes_by_bandwidth_authorities(self, query_run_mock, get_authorities_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor import remote

      # request votes from all the bandwidth authorities

      queries = {}
      downloader = remote.DescriptorDownloader()

      for authority in remote.get_authorities().values():
        if authority.is_bandwidth_authority:
          queries[authority.nickname] = downloader.query(
            '/tor/status-vote/current/authority',
            endpoints = [(authority.address, authority.dir_port)],
          )

      for authority_name, query in queries.items():
        try:
          print "Getting %s's vote from %s:" % (authority_name, query.download_url)

          measured, unmeasured = 0, 0

          for desc in query.run():
            if desc.measured:
              measured += 1
            else:
              unmeasured += 1

          print '  %i measured entries and %i unmeasured' % (measured, unmeasured)
        except Exception as exc:
          print "  failed to get the vote (%s)" % exc

#    get_authorities_mock().values.return_value = [DIRECTORY_AUTHORITIES['gabelmoo'], DIRECTORY_AUTHORITIES['tor26'], DIRECTORY_AUTHORITIES['moria1'], DIRECTORY_AUTHORITIES['maatuska']]
    directory_values = []
    directory_values.append(DIRECTORY_AUTHORITIES['gabelmoo'])
    directory_values[0].address = '212.112.245.170'
    directory_values.append(DIRECTORY_AUTHORITIES['tor26'])
    directory_values.append(DIRECTORY_AUTHORITIES['moria1'])
    directory_values.append(DIRECTORY_AUTHORITIES['maatuska'])
    get_authorities_mock().values.return_value = directory_values
    router_status = []
    # Count for gabelmoo.
    entry = []
    for count in range(5935):
      entry.append(get_router_status_entry_v3({'w': 'Bandwidth=1 Measured=1'}))
    for count in range(1332):
      entry.append(get_router_status_entry_v3())
    router_status.append(entry)
    # Count for tor26.
    entry = []
    for count in range(5735):
      entry.append(get_router_status_entry_v3({'w': 'Bandwidth=1 Measured=1'}))
    for count in range(1690):
      entry.append(get_router_status_entry_v3())
    router_status.append(entry)
    # Count for moria1.
    entry = []
    for count in range(6647):
      entry.append(get_router_status_entry_v3({'w': 'Bandwidth=1 Measured=1'}))
    for count in range(625):
      entry.append(get_router_status_entry_v3())
    router_status.append(entry)
    # Count for maatuska.
    entry = []
    for count in range(6313):
      entry.append(get_router_status_entry_v3({'w': 'Bandwidth=1 Measured=1'}))
    for count in range(1112):
      entry.append(get_router_status_entry_v3())
    router_status.append(entry)
    query_run_mock.side_effect = router_status
    tutorial_example()
    self.assertEqual(VOTES_BY_BANDWIDTH_AUTHORITIES_OUTPUT, stdout_mock.getvalue())
