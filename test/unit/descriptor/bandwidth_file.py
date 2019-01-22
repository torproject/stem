"""
Unit tests for stem.descriptor.bandwidth_file.
"""

import datetime
import unittest

import stem.descriptor

from stem.descriptor.bandwidth_file import BandwidthFile
from test.unit.descriptor import get_resource

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

EXPECTED_MEASUREMENT_1 = {
  'scanner': '/scanner.1/scan-data/bws-0.0:0.8-done-2019-01-13-22:55:22',
  'measured_at': '1547441722',
  'pid_delta': '1.07534299311',
  'updated_at': '1547441722',
  'pid_error_sum': '3.23746667827',
  'nick': 'baldr',
  'node_id': '$D8B9CAA5B818DEFE80857F83FDABBB6429DCFCA0',
  'pid_bw': '47625769',
  'bw': '47600',
  'pid_error': '3.23746667827',
  'circ_fail': '0.0',
}

EXPECTED_MEASUREMENT_2 = {
  'desc_bw_obs_last': '473188',
  'success': '13',
  'desc_bw_obs_mean': '581671',
  'bw_median': '202438',
  'nick': 'Teinetteiine',
  'bw': '1',
  'desc_bw_avg': '1024000',
  'time': '2019-01-13T12:21:29',
  'bw_mean': '184647',
  'error_circ': '0',
  'error_stream': '0',
  'node_id': '$9C7E1AFDACC53228F6FB57B3A08C7D36240B8F6F',
  'error_misc': '0',
}

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

    desc = list(stem.descriptor.parse_file(get_resource('bandwidth_file_v1.0'), 'bandwidth-file 1.0'))[0]

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

    self.assertEqual(94, len(desc.measurements))
    self.assertEqual(EXPECTED_MEASUREMENT_1, desc.measurements['D8B9CAA5B818DEFE80857F83FDABBB6429DCFCA0'])

  def test_format_v1_2(self):
    """
    Parse version 1.2 formatted files.
    """

    desc = list(stem.descriptor.parse_file(get_resource('bandwidth_file_v1.2'), 'bandwidth-file 1.2'))[0]

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

    self.assertEqual(81, len(desc.measurements))
    self.assertEqual(EXPECTED_MEASUREMENT_2, desc.measurements['9C7E1AFDACC53228F6FB57B3A08C7D36240B8F6F'])

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

    content = BandwidthFile.content(OrderedDict([
      ('timestamp', '12345'),
      ('version', '1.2.0'),
      ('content', []),
    ]))

    self.assertEqual(b'12345\nversion=1.2.0\n=====', content)

  @patch('time.time', Mock(return_value = 1410723598.276578))
  def test_new_header_attribute(self):
    """
    Include an unrecognized header field.
    """

    desc = BandwidthFile.create(OrderedDict([('version', '1.1.0'), ('new_header', 'neat stuff')]))
    self.assertEqual(EXPECTED_NEW_HEADER_CONTENT, str(desc))
    self.assertEqual('1.1.0', desc.version)
    self.assertEqual({'version': '1.1.0', 'new_header': 'neat stuff'}, desc.header)

  def test_header_for_v1(self):
    """
    Document version 1.0 predates headers, and as such should be prohibited.
    """

    self.assertRaisesWith(ValueError, 'Headers require BandwidthFile version 1.1 or later', BandwidthFile.create, {'new_header': 'neat stuff'})

  def test_header_alternate_div(self):
    """
    To support backward compatability four character dividers are allowed.
    """

    with open(get_resource('bandwidth_file_v1.2')) as desc_file:
      desc = BandwidthFile.from_str(desc_file.read().replace('=====', '===='))

    self.assertEqual(datetime.datetime(2019, 1, 14, 5, 34, 59), desc.timestamp)
    self.assertEqual('1.2.0', desc.version)
    self.assertEqual(81, len(desc.measurements))

  def test_invalid_timestamp(self):
    """
    Invalid timestamp values.
    """

    test_values = (
      b'',
      b'boo',
      b'123.4',
      b'-123',
    )

    for value in test_values:
      expected_exc = "First line should be a unix timestamp, but was '%s'" % value
      self.assertRaisesWith(ValueError, expected_exc, BandwidthFile.create, {'timestamp': value})
