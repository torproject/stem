"""
Unit tests for stem.descriptor.bandwidth_metric.
"""

import datetime
import unittest

import stem.descriptor
import stem.descriptor.bandwidth_metric

import test.unit.descriptor


class TestBandwidthMetric(unittest.TestCase):
  def test_format_v1_0(self):
    """
    Parse version 1.0 formatted metrics.
    """

    desc = list(stem.descriptor.parse_file(test.unit.descriptor.get_resource('bwauth_v1.0'), 'badnwidth-file 1.0'))[0]

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
    Parse version 1.2 formatted metrics.
    """

    desc = list(stem.descriptor.parse_file(test.unit.descriptor.get_resource('bwauth_v1.2'), 'badnwidth-file 1.2'))[0]

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
