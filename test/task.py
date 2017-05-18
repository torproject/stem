# Copyright 2012-2017, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
:class:`~test.task.Task` that can be ran with :func:`~test.task.run_tasks` to initialize our tests. tasks are...

::

  Initialization Tasks
  |- STEM_VERSION - checks our version of stem
  |- TOR_VERSION - checks our version of tor
  |- PYTHON_VERSION - checks our version of python
  |- CRYPTO_VERSION - checks our version of cryptography
  |- PYNACL_VERSION - checks our version of pynacl
  |- MOCK_VERSION - checks our version of mock
  |- PYFLAKES_VERSION - checks our version of pyflakes
  |- PYCODESTYLE_VERSION - checks our version of pycodestyle
  |- CLEAN_PYC - removes any *.pyc without a corresponding *.py
  |- UNUSED_TESTS - checks to see if any tests are missing from our settings
  |- PYFLAKES_TASK - static checks
  +- PYCODESTYLE_TASK - style checks
"""

import os
import re
import sys
import time

import stem
import stem.prereq
import stem.util.conf
import stem.util.system
import stem.util.test_tools
import stem.version

import test.output
import test.util

from test.output import STATUS, ERROR, NO_NL, println

CONFIG = stem.util.conf.config_dict('test', {
  'integ.test_directory': './test/data',
  'test.unit_tests': '',
  'test.integ_tests': '',
})

SRC_PATHS = [os.path.join(test.util.STEM_BASE, path) for path in (
  'stem',
  'test',
  'run_tests.py',
  'cache_manual.py',
  'cache_fallback_directories.py',
  'setup.py',
  'tor-prompt',
  os.path.join('docs', 'republish.py'),
  os.path.join('docs', 'roles.py'),
)]


def _check_tor_version(tor_path):
  return str(test.util.tor_version(tor_path)).split()[0]


def _clean_orphaned_pyc(paths):
  """
  Deletes any file with a *.pyc extention without a corresponding *.py.

  :param list paths: paths to search for orphaned pyc files
  """

  return ['removed %s' % path for path in stem.util.test_tools.clean_orphaned_pyc(paths)]


def _check_for_unused_tests(paths):
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
      if os.path.normpath(CONFIG['integ.test_directory']) in py_path:
        continue

      with open(py_path) as f:
        file_contents = f.read()

      test_match = re.search('^class (\S*)\(unittest.TestCase\):$', file_contents, re.MULTILINE)

      if test_match:
        class_name = test_match.groups()[0]
        module_name = py_path.replace(os.path.sep, '.')[len(test.util.STEM_BASE) + 1:-3] + '.' + class_name

        if not (module_name in CONFIG['test.unit_tests'] or module_name in CONFIG['test.integ_tests']):
          unused_tests.append(module_name)

  if unused_tests:
    raise ValueError('Test modules are missing from our test/settings.cfg:\n%s' % '\n'.join(unused_tests))


def run(category, *tasks):
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

  def __init__(self, label, runner, args = None, is_required = True, print_result = True, print_runtime = False):
    super(Task, self).__init__()

    self.label = label
    self.runner = runner
    self.args = args
    self.is_required = is_required
    self.print_result = print_result
    self.print_runtime = print_runtime
    self.error = None

    self.is_successful = False
    self.result = None

  def run(self):
    start_time = time.time()
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
      elif self.print_runtime:
        output_msg += ' (%0.1fs)' % (time.time() - start_time)

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


class ModuleVersion(Task):
  def __init__(self, label, modules, prereq_check = None):
    if isinstance(modules, str):
      modules = [modules]  # normalize to a list

    def version_check():
      if prereq_check is None or prereq_check():
        for module in modules:
          if stem.util.test_tools._module_exists(module):
            return __import__(module).__version__

      return 'missing'

    super(ModuleVersion, self).__init__(label, version_check)


STEM_VERSION = Task('checking stem version', lambda: stem.__version__)
TOR_VERSION = Task('checking tor version', _check_tor_version)
PYTHON_VERSION = Task('checking python version', lambda: '.'.join(map(str, sys.version_info[:3])))
CRYPTO_VERSION = ModuleVersion('checking cryptography version', 'cryptography', stem.prereq.is_crypto_available)
PYNACL_VERSION = ModuleVersion('checking pynacl version', 'nacl', stem.prereq._is_pynacl_available)
MOCK_VERSION = ModuleVersion('checking mock version', ['unittest.mock', 'mock'], stem.prereq.is_mock_available)
PYFLAKES_VERSION = ModuleVersion('checking pyflakes version', 'pyflakes')
PYCODESTYLE_VERSION = ModuleVersion('checking pycodestyle version', ['pycodestyle', 'pep8'])
CLEAN_PYC = Task('checking for orphaned .pyc files', _clean_orphaned_pyc, (SRC_PATHS,))

UNUSED_TESTS = Task('checking for unused tests', _check_for_unused_tests, [(
  os.path.join(test.util.STEM_BASE, 'test', 'unit'),
  os.path.join(test.util.STEM_BASE, 'test', 'integ'),
)])

PYFLAKES_TASK = Task(
  'running pyflakes',
  stem.util.test_tools.pyflakes_issues,
  args = (SRC_PATHS,),
  is_required = False,
  print_result = False,
  print_runtime = True,
)

PYCODESTYLE_TASK = Task(
  'running pycodestyle',
  stem.util.test_tools.stylistic_issues,
  args = (SRC_PATHS, True, True, True),
  is_required = False,
  print_result = False,
  print_runtime = True,
)
