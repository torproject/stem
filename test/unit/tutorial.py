"""
Tests for the examples given in stem's tutorial.
"""

import io
import unittest

import stem.descriptor.remote

from unittest.mock import patch

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
