"""
Integration tests for stem.descriptor.* contents.
"""

__all__ = ["reader", "extrainfo_descriptor", "server_descriptor"]

import os

DESCRIPTOR_TEST_DATA = os.path.join(os.path.dirname(__file__), "data")


def get_resource(filename):
  """
  Provides the path for a file in our descriptor data directory.
  """

  return os.path.join(DESCRIPTOR_TEST_DATA, filename)
