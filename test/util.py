# Copyright 2012-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for our test framework.

::

  get_unit_tests - provides our unit tests
  get_integ_tests - provides our integration tests

  get_prereq - provides the tor version required to run the given target
  get_torrc_entries - provides the torrc entries for a given target

Sets of :class:`~test.util.Task` instances can be ran with
:func:`~test.util.run_tasks`. Functions that are intended for easy use with
Tasks are...

::

  Initialization
  |- check_stem_version - checks our version of stem
  |- check_python_version - checks our version of python
  |- check_pycrypto_version - checks our version of pycrypto
  |- check_pyflakes_version - checks our version of pyflakes
  |- check_pycodestyle_version - checks our version of pycodestyle
  |- clean_orphaned_pyc - removes any *.pyc without a corresponding *.py
  +- check_for_unused_tests - checks to see if any tests are missing from our settings
"""

import re
import os
import sys

import stem
import stem.prereq
import stem.util.conf
import stem.util.system
import stem.util.test_tools
import stem.version

import test.output

from test.output import STATUS, ERROR, NO_NL, println

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

# We make some paths relative to stem's base directory (the one above us)
# rather than the process' cwd. This doesn't end with a slash.

STEM_BASE = os.path.sep.join(__file__.split(os.path.sep)[:-2])

# Store new capabilities (events, descriptor entries, etc.)

NEW_CAPABILITIES = []


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


def check_stem_version():
  return stem.__version__


def check_python_version():
  return '.'.join(map(str, sys.version_info[:3]))


def check_pycrypto_version():
  if stem.prereq.is_crypto_available():
    import Crypto
    return Crypto.__version__
  else:
    return 'missing'


def check_mock_version():
  if stem.prereq.is_mock_available():
    try:
      import unittest.mock as mock
    except ImportError:
      import mock

    return mock.__version__
  else:
    return 'missing'


def check_pyflakes_version():
  try:
    import pyflakes
    return pyflakes.__version__
  except ImportError:
    return 'missing'


def check_pycodestyle_version():
  if stem.util.test_tools._module_exists('pycodestyle'):
    import pycodestyle
  elif stem.util.test_tools._module_exists('pep8'):
    import pep8 as pycodestyle
  else:
    return 'missing'

  return pycodestyle.__version__


def clean_orphaned_pyc(paths):
  """
  Deletes any file with a *.pyc extention without a corresponding *.py.

  :param list paths: paths to search for orphaned pyc files
  """

  return ['removed %s' % path for path in stem.util.test_tools.clean_orphaned_pyc(paths)]


def check_for_unused_tests(paths):
  """
  The 'test.unit_tests' and 'test.integ_tests' in our settings.cfg defines the
  tests that we run. We do it this way so that we can control the order in
  which our tests are run but there's a disadvantage: when we add new test
  modules we can easily forget to add it there.

  Checking to see if we have any unittest.TestCase subclasses not covered by
  our settings.

  :param list paths: paths to search for unused tests
  """

  unused_tests = []

  for path in paths:
    for py_path in stem.util.system.files_with_suffix(path, '.py'):
      if _is_test_data(py_path):
        continue

      with open(py_path) as f:
        file_contents = f.read()

      test_match = re.search('^class (\S*)\(unittest.TestCase\):$', file_contents, re.MULTILINE)

      if test_match:
        class_name = test_match.groups()[0]
        module_name = py_path.replace(os.path.sep, '.')[len(STEM_BASE) + 1:-3] + '.' + class_name

        if not (module_name in CONFIG['test.unit_tests'] or module_name in CONFIG['test.integ_tests']):
          unused_tests.append(module_name)

  if unused_tests:
    raise ValueError('Test modules are missing from our test/settings.cfg:\n%s' % '\n'.join(unused_tests))


def register_new_capability(capability_type, msg):
  """
  Register new capability found during the tests.

  :param str capability_type: type of capability this is
  :param str msg: description of what we found
  """

  NEW_CAPABILITIES.append((capability_type, msg))


def _is_test_data(path):
  return os.path.normpath(CONFIG['integ.test_directory']) in path


def run_tasks(category, *tasks):
  """
  Runs a series of :class:`test.util.Task` instances. This simply prints 'done'
  or 'failed' for each unless we fail one that is marked as being required. If
  that happens then we print its error message and call sys.exit().

  :param str category: label for the series of tasks
  :param list tasks: **Task** instances to be ran
  """

  test.output.print_divider(category, True)

  for task in tasks:
    if task is None:
      continue

    task.run()

    if task.is_required and task.error:
      println('\n%s\n' % task.error, ERROR)
      sys.exit(1)

  println()


class Task(object):
  """
  Task we can process while running our tests. The runner can return either a
  message or list of strings for its results.
  """

  def __init__(self, label, runner, args = None, is_required = True, print_result = True):
    super(Task, self).__init__()

    self.label = label
    self.runner = runner
    self.args = args
    self.is_required = is_required
    self.print_result = print_result
    self.error = None

    self.is_successful = False
    self.result = None

  def run(self):
    println('  %s...' % self.label, STATUS, NO_NL)

    padding = 50 - len(self.label)
    println(' ' * padding, NO_NL)

    try:
      if self.args:
        self.result = self.runner(*self.args)
      else:
        self.result = self.runner()

      self.is_successful = True
      output_msg = 'done'

      if self.print_result and isinstance(self.result, str):
        output_msg = self.result

      println(output_msg, STATUS)

      if self.print_result and isinstance(self.result, (list, tuple)):
        for line in self.result:
          println('    %s' % line, STATUS)
    except Exception as exc:
      output_msg = str(exc)

      if not output_msg or self.is_required:
        output_msg = 'failed'

      println(output_msg, ERROR)
      self.error = exc
