"""
Unit tests for stem.descriptor.bandwidth_file.
"""

import datetime
import unittest

import stem.descriptor

from stem.descriptor.bandwidth_file import BandwidthFile
from test.unit.descriptor import get_resource

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

EXPECTED_NEW_HEADER_CONTENT = """
1410723598
version=1.1.0
new_header=neat stuff
=====
""".strip()


class TestBandwidthFile(unittest.TestCase):
  def test_format_v1_0(self):
    """
    Parse version 1.0 formatted files.
    """

    desc = list(stem.descriptor.parse_file(get_resource('bandwidth_file_v1.0'), 'badnwidth-file 1.0'))[0]

    self.assertEqual(datetime.datetime(2019, 1, 14, 17, 41, 29), desc.timestamp)
    self.assertEqual('1.0.0', desc.version)

    self.assertEqual(None, desc.software)
    self.assertEqual(None, desc.software_version)

    self.assertEqual(None, desc.earliest_bandwidth)
    self.assertEqual(None, desc.latest_bandwidth)
    self.assertEqual(None, desc.created_at)
    self.assertEqual(None, desc.generated_at)

    self.assertEqual(None, desc.consensus_size)
    self.assertEqual(None, desc.eligible_count)
    self.assertEqual(None, desc.eligible_percent)
    self.assertEqual(None, desc.min_count)
    self.assertEqual(None, desc.min_percent)

  def test_format_v1_2(self):
    """
    Parse version 1.2 formatted files.
    """

    desc = list(stem.descriptor.parse_file(get_resource('bandwidth_file_v1.2'), 'badnwidth-file 1.2'))[0]

    self.assertEqual(datetime.datetime(2019, 1, 14, 5, 34, 59), desc.timestamp)
    self.assertEqual('1.2.0', desc.version)

    self.assertEqual('sbws', desc.software)
    self.assertEqual('1.0.2', desc.software_version)

    self.assertEqual(datetime.datetime(2019, 1, 4, 5, 35, 29), desc.earliest_bandwidth)
    self.assertEqual(datetime.datetime(2019, 1, 14, 5, 34, 59), desc.latest_bandwidth)
    self.assertEqual(datetime.datetime(2019, 1, 14, 5, 35, 6), desc.created_at)
    self.assertEqual(datetime.datetime(2019, 1, 3, 22, 45, 8), desc.generated_at)

    self.assertEqual(6514, desc.consensus_size)
    self.assertEqual(6256, desc.eligible_count)
    self.assertEqual(96, desc.eligible_percent)
    self.assertEqual(3908, desc.min_count)
    self.assertEqual(60, desc.min_percent)

  @patch('time.time', Mock(return_value = 1410723598.276578))
  def test_minimal_bandwidth_file(self):
    """
    Basic sanity check that we can parse a bandwidth file with minimal
    attributes.
    """

    desc = BandwidthFile.create()

    self.assertEqual('1410723598', str(desc))

    self.assertEqual(datetime.datetime(2014, 9, 14, 19, 39, 58), desc.timestamp)
    self.assertEqual('1.0.0', desc.version)

    self.assertEqual(None, desc.software)
    self.assertEqual(None, desc.software_version)

    self.assertEqual(None, desc.earliest_bandwidth)
    self.assertEqual(None, desc.latest_bandwidth)
    self.assertEqual(None, desc.created_at)
    self.assertEqual(None, desc.generated_at)

    self.assertEqual(None, desc.consensus_size)
    self.assertEqual(None, desc.eligible_count)
    self.assertEqual(None, desc.eligible_percent)
    self.assertEqual(None, desc.min_count)
    self.assertEqual(None, desc.min_percent)

    self.assertEqual({}, desc.header)

  def test_content_example(self):
    """
    Exercise the example in our content method's pydoc.
    """

    content = BandwidthFile.content({
      'timestamp': '12345',
      'version': '1.2.0',
      'content': [],
    })

    self.assertEqual('12345\nversion=1.2.0\n=====', content)

  @patch('time.time', Mock(return_value = 1410723598.276578))
  def test_new_header_attribute(self):
    """
    Include an unrecognized header field.
    """

    desc = BandwidthFile.create({'version': '1.1.0', 'new_header': 'neat stuff'})
    self.assertEqual(EXPECTED_NEW_HEADER_CONTENT, str(desc))
    self.assertEqual('1.1.0', desc.version)
    self.assertEqual({'version': '1.1.0', 'new_header': 'neat stuff'}, desc.header)

  def test_header_for_v1(self):
    """
    Document version 1.0 predates headers, and as such should be prohibited.
    """

    self.assertRaisesWith(ValueError, 'Headers require BandwidthFile version 1.1 or later', BandwidthFile.create, {'new_header': 'neat stuff'})

  def test_invalid_timestamp(self):
    """
    Invalid timestamp values.
    """

    test_values = (
      '',
      'boo',
      '123.4',
      '-123',
    )

    for value in test_values:
      expected_exc = "First line should be a unix timestamp, but was '%s'" % value
      self.assertRaisesWith(ValueError, expected_exc, BandwidthFile.create, {'timestamp': value})
