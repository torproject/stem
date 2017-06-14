"""
Integration tests for stem.descriptor.extrainfo_descriptor.
"""

import os
import unittest

import stem.descriptor
import stem.util.test_tools
import test

from stem.util.test_tools import asynchronous


class TestExtraInfoDescriptor(unittest.TestCase):
  @staticmethod
  def run_tests(args):
    stem.util.test_tools.ASYNC_TESTS['test.integ.descriptor.extrainfo_descriptor.test_cached_descriptor'].run(args.test_dir, threaded = True)

  @asynchronous
  def test_cached_descriptor(test_dir):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """

    descriptor_path = os.path.join(test_dir, 'cached-extrainfo')

    if not os.path.exists(descriptor_path):
      raise stem.util.test_tools.SkipTest('(no cached descriptors)')

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'extra-info 1.0', validate = True):
        for line in desc.get_unrecognized_lines():
          test.register_new_capability('Extra-info Line', line)

        if desc.dir_v2_responses_unknown:
          raise AssertionError('Unrecognized statuses on dirreq-v2-resp lines: %s' % desc.dir_v2_responses_unknown)
        elif desc.dir_v3_responses_unknown:
          raise AssertionError('Unrecognized statuses on dirreq-v3-resp lines: %s' % desc.dir_v3_responses_unknown)
        elif desc.dir_v2_direct_dl_unknown:
          raise AssertionError('Unrecognized stats on dirreq-v2-direct-dl lines: %s' % desc.dir_v2_direct_dl_unknown)
        elif desc.dir_v3_direct_dl_unknown:
          raise AssertionError('Unrecognized stats on dirreq-v3-direct-dl lines: %s' % desc.dir_v2_direct_dl_unknown)
        elif desc.dir_v2_tunneled_dl_unknown:
          raise AssertionError('Unrecognized stats on dirreq-v2-tunneled-dl lines: %s' % desc.dir_v2_tunneled_dl_unknown)
