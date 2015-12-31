"""
Unit tests for stem.descriptor.
"""

import os

__all__ = [
  'export',
  'extrainfo_descriptor',
  'microdescriptor',
  'networkstatus',
  'reader',
  'router_status_entry',
  'server_descriptor',
]

DESCRIPTOR_TEST_DATA = os.path.join(os.path.dirname(__file__), 'data')


def get_resource(filename):
  """
  Provides the path for a file in our descriptor data directory.
  """

  return os.path.join(DESCRIPTOR_TEST_DATA, filename)
