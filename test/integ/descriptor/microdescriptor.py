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
        for line in desc.get_unrecognized_lines():
          register_new_capability('Microdescriptor Line', line)
