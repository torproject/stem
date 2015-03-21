"""
Integration tests for stem.descriptor.microdescriptor.
"""

import os
import unittest

import stem.descriptor
import test.runner

from test.runner import only_run_once

from test.util import register_new_capability


class TestMicrodescriptor(unittest.TestCase):
  @only_run_once
  def test_cached_microdescriptors(self):
    """
    Parses the cached microdescriptor file in our data directory, checking that
    it doesn't raise any validation issues and looking for unrecognized
    descriptor additions.
    """

    descriptor_path = test.runner.get_runner().get_test_dir('cached-microdescs')

    if not os.path.exists(descriptor_path):
      test.runner.skip(self, '(no cached microdescriptors)')
      return

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'microdescriptor 1.0', validate = True):
        unrecognized_lines = desc.get_unrecognized_lines()

        if unrecognized_lines:
          # Forward-compability:
          # 1) SHOULD function at least as it does normally (ignore the unknown)
          # 2) Report each of the aditional (unrecognized) fields to the user

          for line in unrecognized_lines:
            key = line.split()[0]
            register_new_capability(key, 'Microdescriptor Descriptor Entry')
