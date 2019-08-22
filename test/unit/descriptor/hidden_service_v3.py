"""
Unit tests for stem.descriptor.hidden_service for version 3.
"""

import unittest

import stem.descriptor

from test.unit.descriptor import get_resource


class TestHiddenServiceDescriptorV3(unittest.TestCase):
  def test_stub(self):
    # TODO: replace with actual field assertions as the class gets implemented

    with open(get_resource('hidden_service_v3'), 'rb') as descriptor_file:
      desc = next(stem.descriptor.parse_file(descriptor_file, 'hidden-service-descriptor-3 1.0', validate = True))

    self.assertTrue('hs-descriptor 3' in str(desc))
