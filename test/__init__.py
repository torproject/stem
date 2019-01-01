# Copyright 2011-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Unit and integration tests for the stem library. Helpers include...

::

  get_new_capabilities - missing capabilities found while testing
  register_new_capability - note that tor feature stem lacks

  get_all_combinations - provides all combinations of attributes
  tor_version - provides the version of tor we're testing against
"""

import collections
import itertools
import os

import stem.util.enum
import stem.version

__all__ = [
  'network',
  'output',
  'prompt',
  'runner',
]

# Integration targets fall into two categories:
#
# * Run Targets (like RUN_COOKIE and RUN_PTRACE) which customize our torrc.
#   We do an integration test run for each run target we get.
#
# * Attribute Target (like CHROOT and ONLINE) which indicates
#   non-configuration changes to your test runs. These are applied to all
#   integration runs that we perform.

Target = stem.util.enum.UppercaseEnum(
  'ONLINE',
  'RELATIVE',
  'CHROOT',
  'RUN_NONE',
  'RUN_OPEN',
  'RUN_PASSWORD',
  'RUN_COOKIE',
  'RUN_MULTIPLE',
  'RUN_SOCKET',
  'RUN_SCOOKIE',
  'RUN_PTRACE',
  'RUN_ALL',
)

AsyncTestArgs = collections.namedtuple('AsyncTestArgs', ['test_dir', 'tor_cmd'])
TOR_VERSION = None

# We make some paths relative to stem's base directory (the one above us)
# rather than the process' cwd. This doesn't end with a slash.

STEM_BASE = os.path.sep.join(__file__.split(os.path.sep)[:-2])

# Store new capabilities (events, descriptor entries, etc.)

NEW_CAPABILITIES = set()
NEW_CAPABILITIES_SUPPRESSION_TOKENS = set()

# File extensions of contents that should be ignored.

IGNORED_FILE_TYPES = []
GIT_IGNORE_PATH = os.path.join(STEM_BASE, '.gitignore')

if os.path.exists(GIT_IGNORE_PATH):
  with open(GIT_IGNORE_PATH) as ignore_file:
    for line in ignore_file:
      if line.startswith('*.'):
        IGNORED_FILE_TYPES.append(line[2:].strip())

if os.path.exists(os.path.join(STEM_BASE, '.travis.yml')):
    IGNORED_FILE_TYPES.append('.travis.yml')


def get_new_capabilities():
  """
  Provides a list of capabilities tor supports but stem doesn't, as discovered
  while running our tests.

  :returns: **set** of (type, message) tuples for the capabilities
  """

  return NEW_CAPABILITIES


def register_new_capability(capability_type, msg, suppression_token = None):
  """
  Register new capability found during the tests.

  :param str capability_type: type of capability this is
  :param str msg: description of what we found
  :param str suppression_token: skip registration if this token's already been
    provided
  """

  if suppression_token not in NEW_CAPABILITIES_SUPPRESSION_TOKENS:
    NEW_CAPABILITIES.add((capability_type, msg))

    if suppression_token:
      NEW_CAPABILITIES_SUPPRESSION_TOKENS.add(suppression_token)


def get_all_combinations(attr, include_empty = False):
  """
  Provides an iterator for all combinations of a set of attributes. For
  instance...

  ::

    >>> list(test.get_all_combinations(['a', 'b', 'c']))
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


def tor_version(tor_path = None):
  """
  Provides the version of tor we're testing against.

  :param str tor_path: location of tor executable to cehck the version of

  :returns: :class:`~stem.version.Version` of tor invoked by our integration
    tests
  """

  global TOR_VERSION

  if TOR_VERSION is None or tor_path:
    TOR_VERSION = stem.version.get_system_tor_version(tor_path)

  return TOR_VERSION
