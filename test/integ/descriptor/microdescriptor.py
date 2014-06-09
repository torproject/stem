"""
Integration tests for stem.descriptor.microdescriptor.
"""

import os
import unittest

import stem.descriptor
import test.runner


class TestMicrodescriptor(unittest.TestCase):
  def test_cached_microdescriptors(self):
    """
    Parses the cached microdescriptor file in our data directory, checking that
    it doesn't raise any validation issues and looking for unrecognized
    descriptor additions.
    """

    if test.runner.only_run_once(self, 'test_cached_microdescriptors'):
      return

    descriptor_path = test.runner.get_runner().get_test_dir('cached-microdescs')

    if not os.path.exists(descriptor_path):
      test.runner.skip(self, '(no cached microdescriptors)')
      return

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'microdescriptor 1.0'):
        unrecognized_lines = desc.get_unrecognized_lines()

        if unrecognized_lines:
          self.fail('Unrecognized microdescriptor content: %s' % unrecognized_lines)
