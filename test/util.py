# Copyright 2012-2017, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for our test framework.

::

  get_unit_tests - provides our unit tests
  get_integ_tests - provides our integration tests

  get_prereq - provides the tor version required to run the given target
  get_torrc_entries - provides the torrc entries for a given target

  get_protocolinfo_response - provides a ProtocolInfoResponse instance
  get_all_combinations - provides all combinations of attributes
  random_fingerprint - provides a random relay fingerprint
  tor_version - provides the version of tor we're testing against
"""

import hashlib
import itertools
import os

import stem
import stem.util.conf
import stem.util.enum
import stem.version

CONFIG = stem.util.conf.config_dict('test', {
  'target.prereq': {},
  'target.torrc': {},
  'integ.test_directory': './test/data',
  'test.unit_tests': '',
  'test.integ_tests': '',
})

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

TOR_VERSION = None

# We make some paths relative to stem's base directory (the one above us)
# rather than the process' cwd. This doesn't end with a slash.

STEM_BASE = os.path.sep.join(__file__.split(os.path.sep)[:-2])

# Store new capabilities (events, descriptor entries, etc.)

NEW_CAPABILITIES = []
NEW_CAPABILITIES_SUPPRESSION_TOKENS = set()

# File extensions of contents that should be ignored.

IGNORED_FILE_TYPES = []

with open(os.path.join(STEM_BASE, '.gitignore')) as ignore_file:
  for line in ignore_file:
    if line.startswith('*.'):
      IGNORED_FILE_TYPES.append(line[2:].strip())


def get_unit_tests(module_prefix = None):
  """
  Provides the classes for our unit tests.

  :param str module_prefix: only provide the test if the module starts with
    this substring

  :returns: an **iterator** for our unit tests
  """

  if module_prefix and not module_prefix.startswith('test.unit.'):
    module_prefix = 'test.unit.' + module_prefix

  return _get_tests(CONFIG['test.unit_tests'].splitlines(), module_prefix)


def get_integ_tests(module_prefix = None):
  """
  Provides the classes for our integration tests.

  :param str module_prefix: only provide the test if the module starts with
    this substring

  :returns: an **iterator** for our integration tests
  """

  if module_prefix and not module_prefix.startswith('test.integ.'):
    module_prefix = 'test.integ.' + module_prefix

  return _get_tests(CONFIG['test.integ_tests'].splitlines(), module_prefix)


def _get_tests(modules, module_prefix):
  for import_name in modules:
    if import_name:
      module, module_name = import_name.rsplit('.', 1)  # example: util.conf.TestConf

      if not module_prefix or module.startswith(module_prefix):
        yield import_name
      elif module_prefix.startswith(module):
        # single test for this module

        test_module = module_prefix.rsplit('.', 1)[1]
        yield '%s.%s' % (import_name, test_module)


def get_prereq(target):
  """
  Provides the tor version required to run the given target. If the target
  doesn't have any prerequisite then this provides **None**.

  :param Target target: target to provide the prerequisite for

  :returns: :class:`~stem.version.Version` required to run the given target, or
    **None** if there is no prerequisite
  """

  target_prereq = CONFIG['target.prereq'].get(target)

  if target_prereq:
    return stem.version.Requirement[target_prereq]
  else:
    return None


def get_torrc_entries(target):
  """
  Provides the torrc entries used to run the given target.

  :param Target target: target to provide the custom torrc contents of

  :returns: list of :class:`~test.runner.Torrc` entries for the given target

  :raises: **ValueError** if the target.torrc config has entries that don't map
    to test.runner.Torrc
  """

  # converts the 'target.torrc' csv into a list of test.runner.Torrc enums

  config_csv = CONFIG['target.torrc'].get(target)
  torrc_opts = []

  if config_csv:
    for opt in config_csv.split(','):
      opt = opt.strip()

      if opt in test.runner.Torrc.keys():
        torrc_opts.append(test.runner.Torrc[opt])
      else:
        raise ValueError("'%s' isn't a test.runner.Torrc enumeration" % opt)

  return torrc_opts


def get_new_capabilities():
  """
  Provides a list of capabilities tor supports but stem doesn't, as discovered
  while running our tests.

  :returns: **list** of (type, message) tuples for the capabilities
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
    NEW_CAPABILITIES.append((capability_type, msg))

    if suppression_token:
      NEW_CAPABILITIES_SUPPRESSION_TOKENS.add(suppression_token)


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


def get_protocolinfo_response(**attributes):
  """
  Provides a ProtocolInfoResponse, customized with the given attributes. The
  base instance is minimal, with its version set to one and everything else
  left with the default.

  :param dict attributes: attributes to customize the response with

  :returns: stem.response.protocolinfo.ProtocolInfoResponse instance
  """

  protocolinfo_response = stem.response.ControlMessage.from_str('250-PROTOCOLINFO 1\r\n250 OK\r\n', 'PROTOCOLINFO')
  stem.response.convert('PROTOCOLINFO', protocolinfo_response)

  for attr in attributes:
    setattr(protocolinfo_response, attr, attributes[attr])

  return protocolinfo_response


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


import test.runner  # needs to be imported at the end to avoid a circular dependency
