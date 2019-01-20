# Copyright 2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Bandwidth Authority metrics as described in Tor's
`bandwidth-file-spec <https://gitweb.torproject.org/torspec.git/tree/bandwidth-file-spec.txt>`_.

**Module Overview:**

::

  BandwidthFile - Tor bandwidth authority measurements.

.. versionadded:: 1.8.0
"""

import datetime

import stem.util.str_tools

from stem.descriptor import Descriptor


# Converters header attributes to a given type. Malformed fields should be
# ignored according to the spec.

def _str(val):
  return val  # already a str


def _int(val):
  return int(val) if (val and val.isdigit()) else None


def _date(val):
  try:
    return stem.util.str_tools._parse_iso_timestamp(val)
  except ValueError:
    return None  # not an iso formatted date


# mapping of attributes => (header, type)

HEADER_ATTR = {
  'version': ('version', _str),

  'software': ('software', _str),
  'software_version': ('software_version', _str),

  'earliest_bandwidth': ('earliest_bandwidth', _date),
  'latest_bandwidth': ('latest_bandwidth', _date),
  'created_at': ('file_created', _date),
  'generated_at': ('generator_started', _date),

  'consensus_size': ('number_consensus_relays', _int),
  'eligible_count': ('number_eligible_relays', _int),
  'eligible_percent': ('percent_eligible_relays', _int),
  'min_count': ('minimum_number_eligible_relays', _int),
  'min_percent': ('minimum_percent_eligible_relays', _int),
}

HEADER_DEFAULT = {
  'version': '1.0.0',  # version field was added in 1.1.0
}


def _parse_file(descriptor_file, validate = False, **kwargs):
  """
  Iterates over the bandwidth authority metrics in a file.

  :param file descriptor_file: file with descriptor content
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: :class:`stem.descriptor.bandwidth_file.BandwidthFile` object

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **IOError** if the file can't be read
  """

  yield BandwidthFile(descriptor_file.read(), validate, **kwargs)


def _parse_header(descriptor, entries):
  header = {}
  lines = str(descriptor).split('\n')

  # skip the first line, which should be the timestamp

  if lines and lines[0].isdigit():
    lines = lines[1:]

  for line in lines:
    if line == '=====':
      break
    elif line.startswith('node_id='):
      break  # version 1.0 measurement

    if '=' in line:
      key, value = line.split('=', 1)
      header[key] = value
    else:
      raise ValueError("Header expected to be key=value pairs, but had '%s'" % line)

  descriptor.header = header

  for attr, (keyword, cls) in HEADER_ATTR.items():
    setattr(descriptor, attr, cls(header.get(keyword, HEADER_DEFAULT.get(attr))))


def _parse_timestamp(descriptor, entries):
  first_line = str(descriptor).split('\n', 1)[0]

  if first_line.isdigit():
    descriptor.timestamp = datetime.datetime.utcfromtimestamp(int(first_line))
  else:
    raise ValueError("First line should be a unix timestamp, but was '%s'" % first_line)


class BandwidthFile(Descriptor):
  """
  Tor bandwidth authroity measurements.

  :var datetime timestamp: **\*** time when these metrics were published
  :var str version: **\*** document format version

  :var str software: application that generated these metrics
  :var str software_version: version of the application that generated these metrics

  :var datetime earliest_bandwidth: time of the first sampling
  :var datetime latest_bandwidth: time of the last sampling
  :var datetime created_at: time when this file was created
  :var datetime generated_at: time when collection of these metrics started

  :var int consensus_size: number of relays in the consensus
  :var int eligible_count: relays with enough measurements to be included
  :var int eligible_percent: percentage of consensus with enough measurements
  :var int min_count: minimum eligible relays for results to be provided
  :var int min_percent: minimum measured percentage of the consensus

  :var dict header: **\*** header metadata

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  TYPE_ANNOTATION_NAME = 'badnwidth-file'  # TODO: needs an official @type, https://trac.torproject.org/projects/tor/ticket/28615

  ATTRIBUTES = {
    'timestamp': (None, _parse_timestamp),
    'header': ({}, _parse_header),
  }

  ATTRIBUTES.update(dict([(k, (None, _parse_header)) for k in HEADER_ATTR.keys()]))

  def __init__(self, raw_content, validate = False):
    super(BandwidthFile, self).__init__(raw_content, lazy_load = not validate)

    if validate:
      pass  # TODO: implement eager load
