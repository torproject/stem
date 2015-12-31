"""
Unit tests for stem.util.* contents.
"""

import datetime
import time
import unittest

from stem.util import datetime_to_unix

__all__ = [
  'conf',
  'connection',
  'enum',
  'proc',
  'str_tools',
  'system',
  'tor_tools',
]


class TestBaseUtil(unittest.TestCase):
  def test_datetime_to_unix(self):
    self.assertEqual(1344251971.0, datetime_to_unix(datetime.datetime(2012, 8, 6, 11, 19, 31)))
    self.assertTrue((time.time() - datetime_to_unix(datetime.datetime.utcnow())) < 2)
