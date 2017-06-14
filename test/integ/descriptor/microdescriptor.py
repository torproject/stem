"""
Integration tests for stem.descriptor.microdescriptor.
"""

import os
import unittest

import stem.descriptor
import stem.util.test_tools
import test

from stem.util.test_tools import asynchronous


class TestMicrodescriptor(unittest.TestCase):
  @staticmethod
  def run_tests(args):
    stem.util.test_tools.ASYNC_TESTS['test.integ.descriptor.microdescriptor.test_cached_microdescriptors'].run(args.test_dir, threaded = True)

  @asynchronous
  def test_cached_microdescriptors(test_dir):
    """
    Parses the cached microdescriptor file in our data directory, checking that
    it doesn't raise any validation issues and looking for unrecognized
    descriptor additions.
    """

    descriptor_path = os.path.join(test_dir, 'cached-microdescs')

    if not os.path.exists(descriptor_path):
      raise stem.util.test_tools.SkipTest('(no cached descriptors)')

    with open(descriptor_path, 'rb') as descriptor_file:
      for desc in stem.descriptor.parse_file(descriptor_file, 'microdescriptor 1.0', validate = True):
        for line in desc.get_unrecognized_lines():
          test.register_new_capability('Microdescriptor Line', line)
