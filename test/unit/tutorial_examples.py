"""
Tests for the examples given in stem's tutorial.
"""

import StringIO
import unittest

import stem.response

from stem.control import Controller
from test import mocking
from test.mocking import (
  get_relay_server_descriptor,
  get_router_status_entry_v3,
  ROUTER_STATUS_ENTRY_V3_HEADER,
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


def _get_event(content):
  controller_event = mocking.get_message(content)
  stem.response.convert('EVENT', controller_event)
  return controller_event


def _get_circ_event(id, status, hop1, hop2, hop3, purpose):
  path = PATH_CONTENT % (hop1[0], hop1[1], hop2[0], hop2[1], hop3[0], hop3[1])
  content = CIRC_CONTENT % (id, status, path, purpose)
  return _get_event(content)


def _get_router_status(address = None, port = None, nickname = None, fingerprint_base64 = None):
  r_line = ROUTER_STATUS_ENTRY_V3_HEADER[0][1]
  if address:
    r_line = r_line.replace('71.35.150.29', address)
  if port:
    r_line = r_line.replace('9001', port)
  if nickname:
    r_line = r_line.replace('caerSidi', nickname)
  if fingerprint_base64:
    r_line = r_line.replace('p1aag7VwarGxqctS7/fS0y5FU+s', fingerprint_base64)
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
