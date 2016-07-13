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

if stem.prereq.is_python_3():
  str_type = str
  int_type = int
else:
  str_type = unicode
  int_type = long


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


def _hash_attr(obj, *attributes, **kwargs):
  """
  Provide a hash value for the given set of attributes.

  :param Object obj: object to be hashed
  :param list attributes: attribute names to take into account
  :param class parent: parent object to include in the hash value
  """

  my_hash = 0 if kwargs.get('parent') is None else kwargs.get('parent').__hash__(obj)

  for attr in attributes:
    my_hash *= 1024

    attr_value = getattr(obj, attr)

    if attr_value is not None:
      if isinstance(attr_value, dict):
        for k, v in attr_value.items():
          my_hash = (my_hash + hash(k)) * 1024 + hash(v)
      else:
        my_hash += hash(attr_value)

  return my_hash
