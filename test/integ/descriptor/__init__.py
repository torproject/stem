"""
Integration tests for stem.descriptor.* contents.
"""

__all__ = [
  "reader",
  "extrainfo_descriptor",
  "server_descriptor",
  "get_resource",
  "open_desc",
]

import os

import stem.prereq

DESCRIPTOR_TEST_DATA = os.path.join(os.path.dirname(__file__), "data")


def get_resource(filename):
  """
  Provides the path for a file in our descriptor data directory.
  """

  return os.path.join(DESCRIPTOR_TEST_DATA, filename)


def open_desc(filename, absolute = False):
  """
  Provides the file for a given descriptor in our data directory.
  """

  path = filename if absolute else get_resource(filename)

  if stem.prereq.is_python_3():
    return open(path, newline = '')
  else:
    return open(path)
