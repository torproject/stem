"""
Integration tests for stem.descriptor.* contents.
"""

__all__ = [
  'reader',
  'extrainfo_descriptor',
  'microdescriptor',
  'server_descriptor',
  'get_resource',
  'open_desc',
]

import os

DESCRIPTOR_TEST_DATA = os.path.join(os.path.dirname(__file__), 'data')


def get_resource(filename):
  """
  Provides the path for a file in our descriptor data directory.
  """

  return os.path.join(DESCRIPTOR_TEST_DATA, filename)
