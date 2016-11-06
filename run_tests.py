#!/usr/bin/env python
# Copyright 2011-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Runs unit and integration tests. For usage information run this with '--help'.
"""

import os
import sys
import threading
import time
import traceback
import unittest

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

import stem.prereq
import stem.util.conf
import stem.util.enum
import stem.util.log
import stem.util.system
import stem.util.test_tools

import test.arguments
import test.output
import test.runner
import test.util

from test.output import STATUS, SUCCESS, ERROR, NO_NL, STDERR, println
from test.util import STEM_BASE, Task

CONFIG = stem.util.conf.config_dict('test', {
  'integ.test_directory': './test/data',
})

SRC_PATHS = [os.path.join(STEM_BASE, path) for path in (
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

MOCK_UNAVAILABLE_MSG = """\
To run stem's tests you'll need mock...

https://pypi.python.org/pypi/mock/
"""

MOCK_OUT_OF_DATE_MSG = """\
To run stem's tests you'll need mock. You have version %s, but you need
version 0.8.0 or later...

https://pypi.python.org/pypi/mock/
"""

NEW_CAPABILITIES_FOUND = """\
Your version of Tor has capabilities stem currently isn't taking advantage of.
If you're running the latest version of stem then please file a ticket on:

  https://trac.torproject.org/projects/tor/wiki/doc/stem/bugs

New capabilities are:
"""

PYFLAKES_TASK = Task(
  'running pyflakes',
  stem.util.test_tools.pyflakes_issues,
  args = (SRC_PATHS,),
  is_required = False,
  print_result = False,
)

PYCODESTYLE_TASK = Task(
  'running pycodestyle',
  stem.util.test_tools.stylistic_issues,
  args = (SRC_PATHS, True, True, True),
  is_required = False,
  print_result = False,
)

if stem.prereq._is_python_26():
  def assertItemsEqual(self, expected, actual):
    self.assertEqual(set(expected), set(actual))

  unittest.TestCase.assertItemsEqual = assertItemsEqual


def main():
  start_time = time.time()

  try:
    stem.prereq.check_requirements()
  except ImportError as exc:
    println('%s\n' % exc)
    sys.exit(1)

  test_config = stem.util.conf.get_config('test')
  test_config.load(os.path.join(STEM_BASE, 'test', 'settings.cfg'))

  try:
    args = test.arguments.parse(sys.argv[1:])
  except ValueError as exc:
    println(str(exc))
    sys.exit(1)

  if args.quiet:
    test.output.SUPPRESS_STDOUT = True

  if args.print_help:
    println(test.arguments.get_help())
    sys.exit()
  elif not args.run_unit and not args.run_integ:
    println('Nothing to run (for usage provide --help)\n')
    sys.exit()

  if not stem.prereq.is_mock_available():
    try:
      try:
        import unittest.mock as mock
      except ImportError:
        import mock

      println(MOCK_OUT_OF_DATE_MSG % mock.__version__)
    except ImportError:
      println(MOCK_UNAVAILABLE_MSG)

    if stem.util.system.is_available('pip'):
      println("You can get it by running 'sudo pip install mock'.")
    elif stem.util.system.is_available('apt-get'):
      println("You can get it by running 'sudo apt-get install python-mock'.")

    sys.exit(1)

  pyflakes_task, pycodestyle_task = None, None

  if not args.specific_test:
    if stem.util.test_tools.is_pyflakes_available():
      pyflakes_task = PYFLAKES_TASK

    if stem.util.test_tools.is_pycodestyle_available():
      pycodestyle_task = PYCODESTYLE_TASK

  test.util.run_tasks(
    'INITIALISING',
    Task('checking stem version', test.util.check_stem_version),
    Task('checking python version', test.util.check_python_version),
    Task('checking pycrypto version', test.util.check_pycrypto_version),
    Task('checking mock version', test.util.check_mock_version),
    Task('checking pyflakes version', test.util.check_pyflakes_version),
    Task('checking pycodestyle version', test.util.check_pycodestyle_version),
    Task('checking for orphaned .pyc files', test.util.clean_orphaned_pyc, (SRC_PATHS,)),
    Task('checking for unused tests', test.util.check_for_unused_tests, ((os.path.join(STEM_BASE, 'test'),),)),
    pyflakes_task,
    pycodestyle_task,
  )

  # buffer that we log messages into so they can be printed after a test has finished

  logging_buffer = stem.util.log.LogBuffer(args.logging_runlevel)
  stem.util.log.get_logger().addHandler(logging_buffer)

  # filters for how testing output is displayed

  error_tracker = test.output.ErrorTracker()

  output_filters = (
    error_tracker.get_filter(),
    test.output.strip_module,
    test.output.align_results,
    test.output.colorize,
  )

  # Number of tests that we have skipped. This is only available with python
  # 2.7 or later because before that test results didn't have a 'skipped'
  # attribute.

  skipped_tests = 0

  if args.run_unit:
    test.output.print_divider('UNIT TESTS', True)
    error_tracker.set_category('UNIT TEST')

    for test_class in test.util.get_unit_tests(args.specific_test):
      run_result = _run_test(args, test_class, output_filters, logging_buffer)
      skipped_tests += len(getattr(run_result, 'skipped', []))

    println()

  if args.run_integ:
    test.output.print_divider('INTEGRATION TESTS', True)
    integ_runner = test.runner.get_runner()

    # Determine targets we don't meet the prereqs for. Warnings are given about
    # these at the end of the test run so they're more noticeable.

    our_version = stem.version.get_system_tor_version(args.tor_path)
    skipped_targets = []

    for target in args.run_targets:
      # check if we meet this target's tor version prerequisites

      target_prereq = test.util.get_prereq(target)

      if target_prereq and our_version < target_prereq:
        skipped_targets.append(target)
        continue

      error_tracker.set_category(target)

      try:
        integ_runner.start(target, args.attribute_targets, args.tor_path, extra_torrc_opts = test.util.get_torrc_entries(target))

        println('Running tests...\n', STATUS)

        owner = None
        if integ_runner.is_accessible():
          owner = integ_runner.get_tor_controller(True)  # controller to own our main Tor process

        for test_class in test.util.get_integ_tests(args.specific_test):
          run_result = _run_test(args, test_class, output_filters, logging_buffer)
          skipped_tests += len(getattr(run_result, 'skipped', []))

        if owner:
          owner.close()

        # We should have joined on all threads. If not then that indicates a
        # leak that could both likely be a bug and disrupt further targets.

        active_threads = threading.enumerate()

        if len(active_threads) > 1:
          println('Threads lingering after test run:', ERROR)

          for lingering_thread in active_threads:
            println('  %s' % lingering_thread, ERROR)

          break
      except KeyboardInterrupt:
        println('  aborted starting tor: keyboard interrupt\n', ERROR)
        break
      except ValueError as exc:
        # can arise if get_torrc_entries() runs into a bad settings.cfg data

        println(str(exc), ERROR)
        break
      except OSError:
        error_tracker.register_error()
      finally:
        println()
        integ_runner.stop()
        println()

    if skipped_targets:
      println()

      for target in skipped_targets:
        req_version = test.util.get_prereq(target)
        println('Unable to run target %s, this requires tor version %s' % (target, req_version), ERROR)

      println()

  static_check_issues = {}

  if pyflakes_task and pyflakes_task.is_successful:
    for path, issues in pyflakes_task.result.items():
      for issue in issues:
        static_check_issues.setdefault(path, []).append(issue)
  elif not stem.util.test_tools.is_pyflakes_available():
    println('Static error checking requires pyflakes version 0.7.3 or later. Please install it from ...\n  http://pypi.python.org/pypi/pyflakes\n', ERROR)

  if pycodestyle_task and pycodestyle_task.is_successful:
    for path, issues in pycodestyle_task.result.items():
      for issue in issues:
        static_check_issues.setdefault(path, []).append(issue)
  elif not stem.util.test_tools.is_pycodestyle_available():
    println('Style checks require pycodestyle version 1.4.2 or later. Please install it from...\n  http://pypi.python.org/pypi/pycodestyle\n', ERROR)

  _print_static_issues(static_check_issues)

  runtime_label = '(%i seconds)' % (time.time() - start_time)

  if error_tracker.has_errors_occured():
    println('TESTING FAILED %s' % runtime_label, ERROR, STDERR)

    for line in error_tracker:
      println('  %s' % line, ERROR, STDERR)

    error_modules = error_tracker.get_modules()

    if len(error_modules) < 10 and not args.specific_test:
      println('\nYou can re-run just these tests with:\n', ERROR, STDERR)

      for module in error_modules:
        println('  %s --test %s' % (' '.join(sys.argv), module), ERROR, STDERR)
  else:
    if skipped_tests > 0:
      println('%i TESTS WERE SKIPPED' % skipped_tests, STATUS)

    println('TESTING PASSED %s\n' % runtime_label, SUCCESS)

  new_capabilities = test.util.get_new_capabilities()

  if new_capabilities:
    println(NEW_CAPABILITIES_FOUND, ERROR)

    for capability_type, msg in new_capabilities:
      println('  [%s] %s' % (capability_type, msg), ERROR)

  sys.exit(1 if error_tracker.has_errors_occured() else 0)


def _print_static_issues(static_check_issues):
  if static_check_issues:
    println('STATIC CHECKS', STATUS)

    for file_path in static_check_issues:
      println('* %s' % file_path, STATUS)

      # Make a dict of line numbers to its issues. This is so we can both sort
      # by the line number and clear any duplicate messages.

      line_to_issues = {}

      for issue in static_check_issues[file_path]:
        line_to_issues.setdefault(issue.line_number, set()).add((issue.message, issue.line))

      for line_number in sorted(line_to_issues.keys()):
        for msg, line in line_to_issues[line_number]:
          line_count = '%-4s' % line_number
          content = ' | %s' % line.strip() if line.strip() else ''
          println('  line %s - %-40s%s' % (line_count, msg, content))

      println()


def _run_test(args, test_class, output_filters, logging_buffer):
  start_time = time.time()

  if args.verbose:
    test.output.print_divider(test_class)
  else:
    # Test classes look like...
    #
    #   test.unit.util.conf.TestConf.test_parse_enum_csv
    #
    # We want to strip the 'test.unit.' or 'test.integ.' prefix since it's
    # redundant. We also want to drop the test class name. The individual test
    # name at the end it optional (only present if we used the '--test'
    # argument).

    label_comp = test_class.split('.')[2:]
    del label_comp[-1 if label_comp[-1][0].isupper() else -2]
    label = '.'.join(label_comp)

    label = '  %s...' % label
    label = '%-54s' % label

    println(label, STATUS, NO_NL)

  try:
    suite = unittest.TestLoader().loadTestsFromName(test_class)
  except AttributeError as exc:
    if args.specific_test:
      # should only come up if user provided '--test' for something that doesn't exist
      println(' no such test', ERROR)
      return None
    else:
      raise exc
  except Exception as exc:
    println(' failed', ERROR)
    traceback.print_exc(exc)
    return None

  test_results = StringIO()
  run_result = unittest.TextTestRunner(test_results, verbosity=2).run(suite)

  if args.verbose:
    println(test.output.apply_filters(test_results.getvalue(), *output_filters))
  elif not run_result.failures and not run_result.errors:
    println(' success (%0.2fs)' % (time.time() - start_time), SUCCESS)
  else:
    if args.quiet:
      println(label, STATUS, NO_NL, STDERR)
      println(' failed (%0.2fs)' % (time.time() - start_time), ERROR, STDERR)
      println(test.output.apply_filters(test_results.getvalue(), *output_filters), STDERR)
    else:
      println(' failed (%0.2fs)' % (time.time() - start_time), ERROR)
      println(test.output.apply_filters(test_results.getvalue(), *output_filters), NO_NL)

  test.output.print_logging(logging_buffer)

  return run_result


if __name__ == '__main__':
  main()
