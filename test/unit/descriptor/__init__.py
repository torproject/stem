"""
Unit tests for stem.descriptor.
"""

import os

__all__ = [
  'bandwidth_file',
  'collector',
  'data',
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


def read_resource(filename):
  """
  Provides test data.
  """

  with open(get_resource(filename), 'rb') as resource_file:
    return resource_file.read()


def base_expect_invalid_attr(cls, default_attr, default_value, test, desc_attrs, attr = None, expected_value = None):
  return base_expect_invalid_attr_for_text(cls, default_attr, default_value, test, cls.content(desc_attrs), attr, expected_value)


def base_expect_invalid_attr_for_text(cls, default_attr, default_prefix, test, desc_text, attr = None, expected_value = None):
  """
  Asserts that construction will fail due to desc_text having a malformed
  attribute. If an attr is provided then we check that it matches an expected
  value when we're constructed without validation.
  """

  test.assertRaises(ValueError, cls, desc_text, True)
  desc = cls(desc_text, validate = False)

  if attr:
    # check that the invalid attribute matches the expected value when
    # constructed without validation

    test.assertEqual(expected_value, getattr(desc, attr))
  elif default_attr and default_prefix:
    test.assertTrue(getattr(desc, default_attr).startswith(default_prefix))  # check a default attribute

  return desc
