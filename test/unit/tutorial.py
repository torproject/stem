"""
Tests for the examples given in stem's tutorial.
"""

import io
import unittest

import stem.descriptor.remote

from unittest.mock import patch

from stem.descriptor.router_status_entry import RouterStatusEntryV3
from stem.descriptor.networkstatus import NetworkStatusDocumentV3
from stem.descriptor.server_descriptor import RelayDescriptor

MIRROR_MIRROR_OUTPUT = """\
1. speedyexit (102.13 KB/s)
2. speedyexit (102.13 KB/s)
3. speedyexit (102.13 KB/s)
"""


class TestTutorial(unittest.TestCase):
  def tearDown(self):
    # Ensure we don't cache a Mock object as our downloader. Otherwise future
    # tests will understandably be very sad. :P

    stem.descriptor.remote.SINGLETON_DOWNLOADER = None

  @patch('sys.stdout', new_callable = io.StringIO)
  @patch('%s.open' % __name__, create = True)
  def test_mirror_mirror_on_the_wall_3(self, open_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor import parse_file

      for desc in parse_file(open('/home/atagar/.tor/cached-consensus')):
        print('found relay %s (%s)' % (desc.nickname, desc.fingerprint))

    test_file = io.BytesIO(NetworkStatusDocumentV3.content(routers = [RouterStatusEntryV3.create({
      'r': 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0',
    })]))
    test_file.name = '/home/atagar/.tor/cached-consensus'
    open_mock.return_value = test_file

    tutorial_example()
    self.assertEqual('found relay caerSidi (A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB)\n', stdout_mock.getvalue())

  @patch('sys.stdout', new_callable = io.StringIO)
  @patch('stem.descriptor.remote.DescriptorDownloader')
  def test_mirror_mirror_on_the_wall_5(self, downloader_mock, stdout_mock):
    def tutorial_example():
      from stem.descriptor.remote import DescriptorDownloader
      from stem.util import str_tools

      # provides a mapping of observed bandwidth to the relay nicknames
      def get_bw_to_relay():
        bw_to_relay = {}

        downloader = DescriptorDownloader()

        try:
          for desc in downloader.get_server_descriptors().run():
            if desc.exit_policy.is_exiting_allowed():
              bw_to_relay.setdefault(desc.observed_bandwidth, []).append(desc.nickname)
        except Exception as exc:
          print('Unable to retrieve the server descriptors: %s' % exc)

        return bw_to_relay

      # prints the top fifteen relays

      bw_to_relay = get_bw_to_relay()
      count = 1

      for bw_value in sorted(bw_to_relay.keys(), reverse = True):
        for nickname in bw_to_relay[bw_value]:
          print('%i. %s (%s/s)' % (count, nickname, str_tools.size_label(bw_value, 2)))
          count += 1

          if count > 15:
            return

    exit_descriptor = RelayDescriptor.content({'router': 'speedyexit 149.255.97.109 9001 0 0'}).replace(b'reject *:*', b'accept *:*')
    exit_descriptor = RelayDescriptor(exit_descriptor)

    downloader_mock().get_server_descriptors().run.return_value = [
      exit_descriptor,
      RelayDescriptor.create(),  # non-exit
      exit_descriptor,
      exit_descriptor,
    ]

    tutorial_example()
    self.assertEqual(MIRROR_MIRROR_OUTPUT, stdout_mock.getvalue())
