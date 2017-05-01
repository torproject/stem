# Copyright 2012-2017, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for creating mock objects.

::

  get_all_combinations - provides all combinations of attributes
  random_fingerprint - provides a random relay fingerprint

  Instance Constructors
    get_message                     - stem.response.ControlMessage
    get_protocolinfo_response       - stem.response.protocolinfo.ProtocolInfoResponse
"""

import hashlib
import itertools
import os
import re

import stem.descriptor.extrainfo_descriptor
import stem.descriptor.hidden_service_descriptor
import stem.descriptor.microdescriptor
import stem.descriptor.networkstatus
import stem.descriptor.router_status_entry
import stem.descriptor.server_descriptor
import stem.prereq
import stem.response
import stem.util.str_tools


def get_all_combinations(attr, include_empty = False):
  """
  Provides an iterator for all combinations of a set of attributes. For
  instance...

  ::

    >>> list(test.mocking.get_all_combinations(['a', 'b', 'c']))
    [('a',), ('b',), ('c',), ('a', 'b'), ('a', 'c'), ('b', 'c'), ('a', 'b', 'c')]

  :param list attr: attributes to provide combinations for
  :param bool include_empty: includes an entry with zero items if True
  :returns: iterator for all combinations
  """

  # Makes an itertools.product() call for 'i' copies of attr...
  #
  # * itertools.product(attr) => all one-element combinations
  # * itertools.product(attr, attr) => all two-element combinations
  # * ... etc

  if include_empty:
    yield ()

  seen = set()
  for index in range(1, len(attr) + 1):
    product_arg = [attr for _ in range(index)]

    for item in itertools.product(*product_arg):
      # deduplicate, sort, and only provide if we haven't seen it yet
      item = tuple(sorted(set(item)))

      if item not in seen:
        seen.add(item)
        yield item


def random_fingerprint():
  """
  Provides a random relay fingerprint.
  """

  return hashlib.sha1(os.urandom(20)).hexdigest().upper()


def get_message(content, reformat = True):
  """
  Provides a ControlMessage with content modified to be parsable. This makes
  the following changes unless 'reformat' is false...

  * ensures the content ends with a newline
  * newlines are replaced with a carriage return and newline pair

  :param str content: base content for the controller message
  :param str reformat: modifies content to be more accommodating to being parsed

  :returns: stem.response.ControlMessage instance
  """

  if reformat:
    if not content.endswith('\n'):
      content += '\n'

    content = re.sub('([\r]?)\n', '\r\n', content)

  return stem.response.ControlMessage.from_str(content)


def get_protocolinfo_response(**attributes):
  """
  Provides a ProtocolInfoResponse, customized with the given attributes. The
  base instance is minimal, with its version set to one and everything else
  left with the default.

  :param dict attributes: attributes to customize the response with

  :returns: stem.response.protocolinfo.ProtocolInfoResponse instance
  """

  protocolinfo_response = get_message('250-PROTOCOLINFO 1\n250 OK')
  stem.response.convert('PROTOCOLINFO', protocolinfo_response)

  for attr in attributes:
    setattr(protocolinfo_response, attr, attributes[attr])

  return protocolinfo_response
