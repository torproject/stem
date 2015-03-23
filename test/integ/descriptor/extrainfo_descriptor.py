"""
Integration tests for stem.descriptor.extrainfo_descriptor.
"""

import os
import unittest

import stem.descriptor
import test.runner

from test.runner import only_run_once
from test.util import register_new_capability


class TestExtraInfoDescriptor(unittest.TestCase):
  @only_run_once
  def test_cached_descriptor(self):
    """
    Parses the cached descriptor file in our data directory, checking that it
    doesn't raise any validation issues and looking for unrecognized descriptor
    additions.
    """

    descriptor_path = test.runner.get_runner().get_test_dir('cached-extrainfo')

    if not os.path.exists(descriptor_path):
      test.runner.skip(self, '(no cached descriptors)')
      return

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'extra-info 1.0', validate = True):
        for line in desc.get_unrecognized_lines():
          register_new_capability('Extra-info Line', line)

        if desc.dir_v2_responses_unknown:
          self.fail('Unrecognized statuses on dirreq-v2-resp lines: %s' % desc.dir_v2_responses_unknown)
        elif desc.dir_v3_responses_unknown:
          self.fail('Unrecognized statuses on dirreq-v3-resp lines: %s' % desc.dir_v3_responses_unknown)
        elif desc.dir_v2_direct_dl_unknown:
          self.fail('Unrecognized stats on dirreq-v2-direct-dl lines: %s' % desc.dir_v2_direct_dl_unknown)
        elif desc.dir_v3_direct_dl_unknown:
          self.fail('Unrecognized stats on dirreq-v3-direct-dl lines: %s' % desc.dir_v2_direct_dl_unknown)
        elif desc.dir_v2_tunneled_dl_unknown:
          self.fail('Unrecognized stats on dirreq-v2-tunneled-dl lines: %s' % desc.dir_v2_tunneled_dl_unknown)
