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
