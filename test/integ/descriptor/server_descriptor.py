"""
Integration tests for stem.descriptor.server_descriptor.
"""

import os
import unittest

import stem.descriptor
import stem.util.test_tools
import test


class TestServerDescriptor(unittest.TestCase):
  @staticmethod
  def run_tests(test_dir):
    TestServerDescriptor.test_cached_descriptor = stem.util.test_tools.AsyncTest(TestServerDescriptor.test_cached_descriptor, args = (test_dir,), threaded = True).method

  @staticmethod
  def test_cached_descriptor(test_dir):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """

    descriptor_path = os.path.join(test_dir, 'cached-descriptors')

    if not os.path.exists(descriptor_path):
      raise stem.util.test_tools.SkipTest('(no cached descriptors)')

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'server-descriptor 1.0', validate = True):
        # the following attributes should be deprecated, and not appear in the wild

        if desc.read_history_end or desc.write_history_end or desc.eventdns or desc.socks_port:
          raise AssertionError('deprecated attribute appeared on: %s' % desc)

        for line in desc.get_unrecognized_lines():
          test.register_new_capability('Server Descriptor Line', line)
