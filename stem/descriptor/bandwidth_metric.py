# Copyright 2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Bandwidth Authority metrics as described in Tor's
`bandwidth-file-spec <https://gitweb.torproject.org/torspec.git/tree/bandwidth-file-spec.txt>`_.

**Module Overview:**

::

  BandwidthMetric - Tor bandwidth authority measurements.

.. versionadded:: 1.8.0
"""

import datetime

from stem.descriptor import (
  Descriptor,
)


def _parse_file(descriptor_file, validate = False, **kwargs):
  """
  Iterates over the bandwidth authority metrics in a file.

  :param file descriptor_file: file with descriptor content
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: :class:`stem.descriptor.bandwidth_file.BandwidthMetric` object

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  yield BandwidthMetric(descriptor_file.read(), validate, **kwargs)


def _parse_header(descriptor, entries):
  header = {}

  for line in str(descriptor).split('\n'):
    if line == '=====':
      break
    elif line.startswith('node_id='):
      break  # version 1.0 measurement

    if '=' in line:
      key, value = line.split('=', 1)
    elif line.isdigit() and 'timestamp' not in header:
      key, value = 'timestamp', line
    else:
      raise ValueError("Header expected to be key=value pairs, but had '%s'" % line)

    header[key] = value

  descriptor.header = header


def _parse_timestamp(descriptor, entries):
  first_line = str(descriptor).split('\n', 1)[0]

  if first_line.isdigit():
    descriptor.timestamp = datetime.datetime.utcfromtimestamp(int(first_line))
  else:
    raise ValueError("First line should be a unix timestamp, but was '%s'" % first_line)


def _header_attr(name):
  def _parse(descriptor, entries):
    val = descriptor.header.get(name, None)
    setattr(descriptor, name, val)

  return _parse


class BandwidthMetric(Descriptor):
  """
  Tor bandwidth authroity measurements.

  :var datetime timestamp: **\*** time when these metrics were published

  :var dict header: **\*** header metadata attributes

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  TYPE_ANNOTATION_NAME = 'badnwidth-file'  # TODO: needs an official @type

  ATTRIBUTES = {
    'timestamp': (None, _parse_timestamp),
    'header': ({}, _parse_header),
  }

  def __init__(self, raw_content, validate = False):
    super(BandwidthMetric, self).__init__(raw_content, lazy_load = not validate)

    if validate:
      pass  # TODO: implement eager load
