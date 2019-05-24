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

EXPECTED_MEASUREMENT_3 = {
  'desc_bw_obs_last': '70423',
  'desc_bw_obs_mean': '81784',
  'bw_median': '2603',
  'nick': 'whitsun',
  'bw': '1',
  'desc_bw_avg': '1073741824',
  'time': '2019-04-21T10:22:16',
  'bw_mean': '2714',
  'error_circ': '1',
  'error_stream': '0',
  'node_id': '$8F0F49F2341C7F706D5B475815DBD3E5761334B3',
  'error_misc': '0',
  'consensus_bandwidth': '1000',
  'consensus_bandwidth_is_unmeasured': 'False',
  'desc_bw_bur': '1073741824',
  'error_destination': '0',
  'error_second_relay': '0',
  'master_key_ed25519': 'acShTw35dmVSTkhMdmo9RFRLsP4QV+qOZrEJQubnvWY',
  'relay_in_recent_consensus_count': '22',
  'relay_recent_measurement_attempt_count': '1',
  'relay_recent_measurements_excluded_error_count': '1',
  'relay_recent_priority_list_count': '1',
  'success': '3',
}

EXPECTED_NEW_HEADER_CONTENT = """
1410723598
version=1.1.0
new_header=neat stuff
=====
""".strip()

WRONG_VERSION_POSITION = b"""
1410723598
file_created=2019-01-14T05:35:06
version=1.1.0
=====
""".strip()

RIGHT_VERSION_POSITION = b"""
1410723598
version=1.1.0
file_created=2019-01-14T05:35:06
=====
""".strip()


class TestBandwidthFile(unittest.TestCase):
  def test_from_str(self):
    sig = BandwidthFile.create()
    self.assertEqual(sig, BandwidthFile.from_str(str(sig)))

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

    self.assertEqual(None, desc.scanner_country)
    self.assertEqual(None, desc.destinations_countries)
    self.assertEqual(None, desc.time_to_report_half_network)

    stats = desc.recent_stats
    self.assertEqual(None, stats.consensus_count)
    self.assertEqual(None, stats.prioritized_relays)
    self.assertEqual(None, stats.prioritized_relay_lists)
    self.assertEqual(None, stats.measurement_attempts)
    self.assertEqual(None, stats.measurement_failures)

    relay_failures = stats.relay_failures
    self.assertEqual(None, relay_failures.no_measurement)
    self.assertEqual(None, relay_failures.insuffient_period)
    self.assertEqual(None, relay_failures.insufficient_measurements)
    self.assertEqual(None, relay_failures.stale)

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

    self.assertEqual(None, desc.scanner_country)
    self.assertEqual(None, desc.destinations_countries)
    self.assertEqual(None, desc.time_to_report_half_network)

    stats = desc.recent_stats
    self.assertEqual(None, stats.consensus_count)
    self.assertEqual(None, stats.prioritized_relays)
    self.assertEqual(None, stats.prioritized_relay_lists)
    self.assertEqual(None, stats.measurement_attempts)
    self.assertEqual(None, stats.measurement_failures)

    relay_failures = stats.relay_failures
    self.assertEqual(None, relay_failures.no_measurement)
    self.assertEqual(None, relay_failures.insuffient_period)
    self.assertEqual(None, relay_failures.insufficient_measurements)
    self.assertEqual(None, relay_failures.stale)

    self.assertEqual(81, len(desc.measurements))
    self.assertEqual(EXPECTED_MEASUREMENT_2, desc.measurements['9C7E1AFDACC53228F6FB57B3A08C7D36240B8F6F'])

  def test_format_v1_4(self):
    """
    Parse version 1.4 formatted files.
    """

    desc = list(stem.descriptor.parse_file(get_resource('bandwidth_file_v1.4'), 'bandwidth-file 1.4'))[0]

    self.assertEqual(datetime.datetime(2019, 4, 21, 21, 34, 57), desc.timestamp)
    self.assertEqual('1.4.0', desc.version)

    self.assertEqual('sbws', desc.software)
    self.assertEqual('1.1.0', desc.software_version)

    self.assertEqual(datetime.datetime(2019, 4, 16, 21, 35, 7), desc.earliest_bandwidth)
    self.assertEqual(datetime.datetime(2019, 4, 21, 21, 34, 57), desc.latest_bandwidth)
    self.assertEqual(datetime.datetime(2019, 4, 21, 21, 35, 4), desc.created_at)
    self.assertEqual(datetime.datetime(2019, 4, 20, 11, 40, 1), desc.generated_at)

    self.assertEqual(6684, desc.consensus_size)
    self.assertEqual(6459, desc.eligible_count)
    self.assertEqual(97, desc.eligible_percent)
    self.assertEqual(4010, desc.min_count)
    self.assertEqual(60, desc.min_percent)

    self.assertEqual('US', desc.scanner_country)
    self.assertEqual(['ZZ'], desc.destinations_countries)
    self.assertEqual(223519, desc.time_to_report_half_network)

    stats = desc.recent_stats
    self.assertEqual(34, stats.consensus_count)
    self.assertEqual(86417, stats.prioritized_relays)
    self.assertEqual(260, stats.prioritized_relay_lists)
    self.assertEqual(86417, stats.measurement_attempts)
    self.assertEqual(57023, stats.measurement_failures)

    relay_failures = stats.relay_failures
    self.assertEqual(788, relay_failures.no_measurement)
    self.assertEqual(182, relay_failures.insuffient_period)
    self.assertEqual(663, relay_failures.insufficient_measurements)
    self.assertEqual(0, relay_failures.stale)

    self.assertEqual(58, len(desc.measurements))
    self.assertEqual(EXPECTED_MEASUREMENT_3, desc.measurements['8F0F49F2341C7F706D5B475815DBD3E5761334B3'])

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

  def test_version_position(self):
    """
    Our 'version' header must be in the second position if validated, but
    otherwise doesn't matter. (:trac:`29539`)
    """

    desc = BandwidthFile.from_str(WRONG_VERSION_POSITION)
    self.assertEqual('1.1.0', desc.version)

    self.assertRaisesWith(ValueError, "The 'version' header must be in the second position", BandwidthFile.from_str, WRONG_VERSION_POSITION, validate = True)

    content = BandwidthFile.content(OrderedDict([
      ('timestamp', '1410723598'),
      ('file_created', '2019-01-14T05:35:06'),
      ('version', '1.1.0'),
      ('content', []),
    ]))

    self.assertEqual(RIGHT_VERSION_POSITION, content)

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
