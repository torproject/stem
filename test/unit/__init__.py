"""
Unit tests for the stem library.
"""

__all__ = [
  'connection',
  'control',
  'descriptor',
  'exit_policy',
  'socket',
  'util',
  'version',
]


import os
import test.util


def exec_documentation_example(filename):
  path = os.path.join(test.util.STEM_BASE, 'docs', '_static', 'example', filename)

  with open(path) as f:
    code = compile(f.read(), path, 'exec')
    exec(code)
