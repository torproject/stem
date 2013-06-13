"""
Tests for the examples given in stem's tutorial.
"""

import io
import StringIO
import unittest

from mock import Mock, patch

from stem.control import Controller
from stem.descriptor.reader import DescriptorReader
from stem.descriptor.server_descriptor import RelayDescriptor
from test import mocking

MIRROR_MIRROR_OUTPUT = """\
1. speedyexit (102.13 KB/s)
2. speedyexit (102.13 KB/s)
3. speedyexit (102.13 KB/s)
"""


class TestTutorial(unittest.TestCase):
  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_the_little_relay_that_could(self, from_port_mock, stdout_mock):
    def tutorial_example():
      from stem.control import Controller

      with Controller.from_port(control_port = 9051) as controller:
        controller.authenticate()  # provide the password here if you set one

        bytes_read = controller.get_info("traffic/read")
        bytes_written = controller.get_info("traffic/written")

        print "My Tor relay has read %s bytes and written %s." % (bytes_read, bytes_written)

    controller = from_port_mock().__enter__()
    controller.get_info.side_effect = lambda arg: {
      'traffic/read': '33406',
      'traffic/written': '29649',
    }[arg]

    tutorial_example()
    self.assertEqual("My Tor relay has read 33406 bytes and written 29649.\n", stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  def test_mirror_mirror_on_the_wall_1(self, from_port_mock, stdout_mock):
    def tutorial_example():
      from stem.control import Controller

      with Controller.from_port(control_port = 9051) as controller:
        controller.authenticate()

        for desc in controller.get_network_statuses():
          print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

    controller = from_port_mock().__enter__()
    controller.get_network_statuses.return_value = [mocking.get_router_status_entry_v2()]

    tutorial_example()
    self.assertEqual("found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n", stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('%s.open' % __name__, create = True)
  def test_mirror_mirror_on_the_wall_2(self, open_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor import parse_file

      for desc in parse_file(open("/home/atagar/.tor/cached-consensus")):
        print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

    test_file = io.BytesIO(mocking.get_network_status_document_v3(
      routers = [mocking.get_router_status_entry_v3()],
      content = True,
    ))

    test_file.name = "/home/atagar/.tor/cached-consensus"
    open_mock.return_value = test_file

    tutorial_example()
    self.assertEqual("found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n", stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.descriptor.reader.DescriptorReader', spec = DescriptorReader)
  @patch('stem.descriptor.server_descriptor.RelayDescriptor._verify_digest', Mock())
  def test_mirror_mirror_on_the_wall_3(self, reader_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor.reader import DescriptorReader

      with DescriptorReader(["/home/atagar/server-descriptors-2013-03.tar"]) as reader:
        for desc in reader:
          print "found relay %s (%s)" % (desc.nickname, desc.fingerprint)

    reader = reader_mock().__enter__()
    reader.__iter__.return_value = iter([mocking.get_relay_server_descriptor()])

    tutorial_example()
    self.assertEqual("found relay caerSidi (None)\n", stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = StringIO.StringIO)
  @patch('stem.control.Controller.from_port', spec = Controller)
  @patch('stem.descriptor.server_descriptor.RelayDescriptor._verify_digest', Mock())
  def test_mirror_mirror_on_the_wall_4(self, from_port_mock, stdout_mock):
    def tutorial_example():
      from stem.control import Controller
      from stem.util import str_tools

      # provides a mapping of observed bandwidth to the relay nicknames
      def get_bw_to_relay():
        bw_to_relay = {}

        with Controller.from_port(control_port = 9051) as controller:
          controller.authenticate()

          for desc in controller.get_server_descriptors():
            if desc.exit_policy.is_exiting_allowed():
              bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)

        return bw_to_relay

      # prints the top fifteen relays

      bw_to_relay = get_bw_to_relay()
      count = 1

      for bw_value in sorted(bw_to_relay.keys(), reverse = True):
        for nickname in bw_to_relay[bw_value]:
          print "%i. %s (%s/s)" % (count, nickname, str_tools.get_size_label(bw_value, 2))
          count += 1

          if count > 15:
            return

    exit_descriptor = mocking.get_relay_server_descriptor({
      'router': 'speedyexit 149.255.97.109 9001 0 0'
    }, content = True).replace(b'reject *:*', b'accept *:*')

    exit_descriptor = mocking.sign_descriptor_content(exit_descriptor)
    exit_descriptor = RelayDescriptor(exit_descriptor)

    controller = from_port_mock().__enter__()
    controller.get_server_descriptors.return_value = [
      exit_descriptor,
      mocking.get_relay_server_descriptor(),  # non-exit
      exit_descriptor,
      exit_descriptor,
    ]

    tutorial_example()
    self.assertEqual(MIRROR_MIRROR_OUTPUT, stdout_mock.getvalue())
