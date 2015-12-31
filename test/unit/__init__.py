"""
Unit tests for the stem library.
"""

import os
import test.util

__all__ = [
  'connection',
  'control',
  'descriptor',
  'exit_policy',
  'socket',
  'util',
  'version',
]


def exec_documentation_example(filename):
  path = os.path.join(test.util.STEM_BASE, 'docs', '_static', 'example', filename)

  with open(path) as f:
    code = compile(f.read(), path, 'exec')
    exec(code)
