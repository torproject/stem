"""
Integration tests for stem.descriptor.server_descriptor.
"""

import os
import unittest

import stem.descriptor

import test.runner


class TestServerDescriptor(unittest.TestCase):
  def test_cached_descriptor(self):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """

    # lengthy test and uneffected by targets, so only run once

    if test.runner.only_run_once(self, 'test_cached_descriptor'):
      return

    descriptor_path = test.runner.get_runner().get_test_dir('cached-descriptors')

    if not os.path.exists(descriptor_path):
      test.runner.skip(self, '(no cached descriptors)')
      return

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0'):
        # the following attributes should be deprecated, and not appear in the wild
        self.assertEquals(None, desc.read_history_end)
        self.assertEquals(None, desc.write_history_end)
        self.assertEquals(None, desc.eventdns)
        self.assertEquals(None, desc.socks_port)

        unrecognized_lines = desc.get_unrecognized_lines()

        if unrecognized_lines:
          # TODO: This isn't actually a problem, and rather than failing we
          # should alert the user about these entries at the end of the tests
          # (along with new events, getinfo options, and such). For now though
          # there doesn't seem to be anything in practice to trigger this so
          # failing to get our attention if it does.

          self.fail('Unrecognized descriptor content: %s' % unrecognized_lines)
