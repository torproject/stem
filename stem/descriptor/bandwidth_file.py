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
import io
import time

import stem.util.str_tools

from stem.descriptor import (
  _mappings_for,
  Descriptor,
)

HEADER_DIV = '====='


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
  content = io.BytesIO(descriptor.get_bytes())

  content.readline()  # skip the first line, which should be the timestamp

  while True:
    line = content.readline().strip()

    if not line:
      break  # end of the content
    elif line == HEADER_DIV:
      break  # end of header
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
  first_line = io.BytesIO(descriptor.get_bytes()).readline().strip()

  if first_line.isdigit():
    descriptor.timestamp = datetime.datetime.utcfromtimestamp(int(first_line))
  else:
    raise ValueError("First line should be a unix timestamp, but was '%s'" % first_line)


def _parse_body(descriptor, entries):
  # In version 1.0.0 the body is everything after the first line. Otherwise
  # it's everything after the header's divider.

  content = io.BytesIO(descriptor.get_bytes())

  if descriptor.version == '1.0.0':
    content.readline()  # skip the first line
  else:
    while content.readline().strip() != HEADER_DIV:
      pass  # skip the header

  measurements = {}

  for line in content.readlines():
    attr = dict(_mappings_for('measurement', line.strip()))

    if 'node_id' not in attr:
      raise ValueError("Every meaurement must include 'node_id': %s" % line.strip())
    elif attr['node_id'] in measurements:
      # Relay is listed multiple times. This is a bug for the bandwidth
      # authority that made this descriptor, but according to the spec
      # should be ignored by parsers.

      continue

    fingerprint = attr['node_id'].lstrip('$')  # bwauths prefix fingerprints with '$'
    measurements[fingerprint] = attr

  descriptor.measurements = measurements


class BandwidthFile(Descriptor):
  """
  Tor bandwidth authroity measurements.

  :var dict measurements: **\*** mapping of relay fingerprints to their
    bandwidth measurement metadata

  :var dict header: **\*** header metadata
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

  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  TYPE_ANNOTATION_NAME = 'badnwidth-file'  # TODO: needs an official @type, https://trac.torproject.org/projects/tor/ticket/28615

  ATTRIBUTES = {
    'timestamp': (None, _parse_timestamp),
    'header': ({}, _parse_header),
    'measurements': ({}, _parse_body),
  }

  ATTRIBUTES.update(dict([(k, (None, _parse_header)) for k in HEADER_ATTR.keys()]))

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False):
    """
    Creates descriptor content with the given attributes. This descriptor type
    differs somewhat from others and treats our attr/exclude attributes as
    follows...

      * 'timestamp' is a reserved key for our mandatory header unix timestamp.

      * 'content' is a reserved key for a list of our bandwidth measurements.

      * All other keys are treated as header fields.

    For example...

    ::

      BandwidthFile.content({
        'timestamp': '12345',
        'version': '1.2.0',
        'content': [],
      })
    """

    if sign:
      raise NotImplementedError('Signing of %s not implemented' % cls.__name__)

    header = dict(attr) if attr is not None else {}
    timestamp = header.pop('timestamp', str(int(time.time())))
    content = header.pop('content', [])
    version = header.get('version', HEADER_DEFAULT.get('version'))

    lines = []

    if 'timestamp' not in exclude:
      lines.append(timestamp)

    if version == '1.0.0' and header:
      raise ValueError('Headers require BandwidthFile version 1.1 or later')
    elif version != '1.0.0':
      for k, v in header.items():
        lines.append('%s=%s' % (k, v))

      lines.append(HEADER_DIV)

    for measurement in content:
      lines.append(measurement)  # TODO: replace when we have a measurement struct

    return '\n'.join(lines)

  def __init__(self, raw_content, validate = False):
    super(BandwidthFile, self).__init__(raw_content, lazy_load = not validate)

    if validate:
      _parse_timestamp(self, None)
      _parse_header(self, None)
      _parse_body(self, None)
