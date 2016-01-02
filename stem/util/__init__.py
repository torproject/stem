# Copyright 2011-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Utility functions used by the stem library.
"""

import datetime

import stem.prereq

__all__ = [
  'conf',
  'connection',
  'enum',
  'log',
  'lru_cache',
  'ordereddict',
  'proc',
  'system',
  'term',
  'test_tools',
  'tor_tools',
  'datetime_to_unix',
]


def datetime_to_unix(timestamp):
  """
  Converts a utc datetime object to a unix timestamp.

  .. versionadded:: 1.5.0

  :param datetime timestamp: timestamp to be converted

  :returns: **float** for the unix timestamp of the given datetime object
  """

  if stem.prereq._is_python_26():
    return int(timestamp.strftime('%s')) - int(datetime.datetime(1970, 1, 1).strftime('%s')) + 3600
  else:
    return (timestamp - datetime.datetime(1970, 1, 1)).total_seconds()
