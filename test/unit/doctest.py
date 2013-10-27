"""
Tests examples from our documentation.
"""

from __future__ import absolute_import

import doctest
import os
import unittest

import stem.version

import test.util

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch


class TestDocumentation(unittest.TestCase):
  def test_examples(self):
    cwd = os.getcwd()

    for path in test.util._get_files_with_suffix(os.path.join(test.util.STEM_BASE, 'stem')):
      path = '../../' + path[len(cwd) + 1:]
      test_run = None

      if path.endswith('/stem/util/conf.py'):
        pass  # too much context to easily test
      elif path.endswith('/stem/response/__init__.py'):
        pass  # the escaped slashes seem to be confusing doctest
      elif path.endswith('/stem/control.py'):
        pass  # examples refrence a control instance
      elif path.endswith('/stem/version.py'):
        with patch('stem.version.get_system_tor_version', Mock(return_value = stem.version.Version('0.2.1.30'))):
          test_run = doctest.testfile(path)
      else:
        test_run = doctest.testfile(path)

      if test_run and test_run.failed > 0:
        self.fail()
