# Copyright 2013-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for `TorDNSEL <https://www.torproject.org/projects/tordnsel.html.en>`_
exit list files.

::

  TorDNSEL - Exit list provided by TorDNSEL
"""

import datetime

import stem.util.connection
import stem.util.str_tools
import stem.util.tor_tools

from typing import Any, BinaryIO, Callable, Dict, Iterator, List, Optional, Tuple

from stem.descriptor import (
  ENTRY_TYPE,
  Descriptor,
  _read_until_keywords,
  _descriptor_components,
)


def _parse_file(tordnsel_file: BinaryIO, validate: bool = False, **kwargs: Any) -> Iterator['stem.descriptor.tordnsel.TorDNSEL']:
  """
  Iterates over a tordnsel file.

  :returns: iterator for :class:`~stem.descriptor.tordnsel.TorDNSEL`
    instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is **True**
    * **OSError** if the file can't be read
  """

  if kwargs:
    raise ValueError("TorDNSEL doesn't support additional arguments: %s" % kwargs)

  # skip content prior to the first ExitNode
  _read_until_keywords('ExitNode', tordnsel_file, skip = True)

  while True:
    contents = _read_until_keywords('ExitAddress', tordnsel_file)
    contents += _read_until_keywords('ExitNode', tordnsel_file)

    if contents:
      yield TorDNSEL(bytes.join(b'', contents), validate)
    else:
      break  # done parsing file


class TorDNSEL(Descriptor):
  """
  TorDNSEL descriptor (`exitlist specification
  <https://www.torproject.org/tordnsel/exitlist-spec.txt>`_)

  :var str fingerprint: **\\*** authority's fingerprint
  :var datetime published: **\\*** time in UTC when this descriptor was made
  :var datetime last_status: **\\*** time in UTC when the relay was seen in a v2 network status
  :var list exit_addresses: **\\*** list of (str address, datetime date) tuples consisting of the found IPv4 exit address and the time

  **\\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """

  TYPE_ANNOTATION_NAME = 'tordnsel'

  def __init__(self, raw_contents: bytes, validate: bool) -> None:
    super(TorDNSEL, self).__init__(raw_contents)
    entries = _descriptor_components(raw_contents, validate)

    self.fingerprint = None  # type: Optional[str]
    self.published = None  # type: Optional[datetime.datetime]
    self.last_status = None  # type: Optional[datetime.datetime]
    self.exit_addresses = []  # type: List[Tuple[str, datetime.datetime]]

    self._parse(entries, validate)

  def _parse(self, entries: ENTRY_TYPE, validate: bool, parser_for_line: Optional[Dict[str, Callable]] = None) -> None:
    if parser_for_line:
      raise ValueError('parser_for_line is unused by TorDNSEL')

    for keyword, values in list(entries.items()):
      value, block_type, block_content = values[0]

      if validate and block_content:
        raise ValueError('Unexpected block content: %s' % block_content)

      if keyword == 'ExitNode':
        if validate and not stem.util.tor_tools.is_valid_fingerprint(value):
          raise ValueError('Tor relay fingerprints consist of forty hex digits: %s' % value)

        self.fingerprint = value
      elif keyword == 'Published':
        try:
          self.published = stem.util.str_tools._parse_timestamp(value, datetime.timezone.utc)
        except ValueError:
          if validate:
            raise ValueError("Published time wasn't parsable: %s" % value)
      elif keyword == 'LastStatus':
        try:
          self.last_status = stem.util.str_tools._parse_timestamp(value, datetime.timezone.utc)
        except ValueError:
          if validate:
            raise ValueError("LastStatus time wasn't parsable: %s" % value)
      elif keyword == 'ExitAddress':
        for value, block_type, block_content in values:
          address, date_str = value.split(' ', 1)

          if validate:
            if not stem.util.connection.is_valid_ipv4_address(address):
              raise ValueError("ExitAddress isn't a valid IPv4 address: %s" % address)
            elif block_content:
              raise ValueError('Unexpected block content: %s' % block_content)

          try:
            date = stem.util.str_tools._parse_timestamp(date_str, datetime.timezone.utc)
            self.exit_addresses.append((address, date))
          except ValueError:
            if validate:
              raise ValueError("ExitAddress found time wasn't parsable: %s" % value)
      elif validate:
        raise ValueError('Unrecognized keyword: %s' % keyword)
