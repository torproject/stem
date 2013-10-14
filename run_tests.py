#!/usr/bin/env python
# Copyright 2011-2013, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Runs unit and integration tests. For usage information run this with '--help'.
"""

import collections
import getopt
import os
import StringIO
import sys
import threading
import time
import unittest

import stem.prereq
import stem.util.conf
import stem.util.enum
import stem.util.log
import stem.util.system

import test.output
import test.runner
import test.util

from test.output import STATUS, SUCCESS, ERROR, println
from test.util import STEM_BASE, Target, Task

# Our default arguments. The _get_args() function provides a named tuple of
# this merged with our argv.
#
# Integration targets fall into two categories:
#
# * Run Targets (like RUN_COOKIE and RUN_PTRACE) which customize our torrc.
#   We do an integration test run for each run target we get.
#
# * Attribute Target (like CHROOT and ONLINE) which indicates
#   non-configuration changes to your test runs. These are applied to all
#   integration runs that we perform.

ARGS = {
  'run_unit': False,
  'run_integ': False,
  'run_style': False,
  'run_python3': False,
  'run_python3_clean': False,
  'test_prefix': None,
  'logging_runlevel': None,
  'tor_path': 'tor',
  'run_targets': [Target.RUN_OPEN],
  'attribute_targets': [],
  'print_help': False,
}

OPT = "auist:l:h"
OPT_EXPANDED = ["all", "unit", "integ", "style", "python3", "clean", "targets=", "test=", "log=", "tor=", "help"]

CONFIG = stem.util.conf.config_dict("test", {
  "target.torrc": {},
  "integ.test_directory": "./test/data",
})

SRC_PATHS = [os.path.join(STEM_BASE, path) for path in (
  'stem',
  'test',
  'run_tests.py',
  os.path.join('docs', 'republish.py'),
  os.path.join('docs', 'roles.py'),
)]

LOG_TYPE_ERROR = """\
'%s' isn't a logging runlevel, use one of the following instead:
  TRACE, DEBUG, INFO, NOTICE, WARN, ERROR
"""

MOCK_UNAVAILABLE_MSG = """\
To run stem's tests you'll need mock...

https://pypi.python.org/pypi/mock/
"""

MOCK_OUT_OF_DATE_MSG = """\
To run stem's tests you'll need mock. You have version %s, but you need
version 0.8.0 or later...

https://pypi.python.org/pypi/mock/
"""


def main():
  start_time = time.time()

  try:
    stem.prereq.check_requirements()
  except ImportError as exc:
    println("%s\n" % exc)
    sys.exit(1)

  test_config = stem.util.conf.get_config("test")
  test_config.load(os.path.join(STEM_BASE, "test", "settings.cfg"))

  try:
    args = _get_args(sys.argv[1:])
  except getopt.GetoptError as exc:
    println("%s (for usage provide --help)" % exc)
    sys.exit(1)
  except ValueError as exc:
    println(str(exc))
    sys.exit(1)

  if args.print_help:
    println(test.util.get_help_message())
    sys.exit()
  elif not args.run_unit and not args.run_integ and not args.run_style:
    println("Nothing to run (for usage provide --help)\n")
    sys.exit()

  if not stem.prereq.is_mock_available():
    try:
      try:
        import unittest.mock
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

  test.util.run_tasks(
    "INITIALISING",
    Task("checking stem version", test.util.check_stem_version),
    Task("checking python version", test.util.check_python_version),
    Task("checking pycrypto version", test.util.check_pycrypto_version),
    Task("checking mock version", test.util.check_mock_version),
    Task("checking pyflakes version", test.util.check_pyflakes_version),
    Task("checking pep8 version", test.util.check_pep8_version),
    Task("checking for orphaned .pyc files", test.util.clean_orphaned_pyc, (SRC_PATHS,)),
    Task("checking for unused tests", test.util.check_for_unused_tests, ((os.path.join(STEM_BASE, 'test'),),)),
  )

  if args.run_python3 and sys.version_info[0] != 3:
    test.util.run_tasks(
      "EXPORTING TO PYTHON 3",
      Task("checking requirements", test.util.python3_prereq),
      Task("cleaning prior export", test.util.python3_clean, (not args.run_python3_clean,)),
      Task("exporting python 3 copy", test.util.python3_copy_stem),
      Task("running tests", test.util.python3_run_tests),
    )

    println("BUG: python3_run_tests() should have terminated our process", ERROR)
    sys.exit(1)

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
    test.output.print_divider("UNIT TESTS", True)
    error_tracker.set_category("UNIT TEST")

    for test_class in test.util.get_unit_tests(args.test_prefix):
      run_result = _run_test(test_class, output_filters, logging_buffer)
      skipped_tests += len(getattr(run_result, 'skipped', []))

    println()

  if args.run_integ:
    test.output.print_divider("INTEGRATION TESTS", True)
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

        println("Running tests...\n", STATUS)

        owner = None
        if integ_runner.is_accessible():
          owner = integ_runner.get_tor_controller(True)  # controller to own our main Tor process

        for test_class in test.util.get_integ_tests(args.test_prefix):
          run_result = _run_test(test_class, output_filters, logging_buffer)
          skipped_tests += len(getattr(run_result, 'skipped', []))

        if owner:
          owner.close()

        # We should have joined on all threads. If not then that indicates a
        # leak that could both likely be a bug and disrupt further targets.

        active_threads = threading.enumerate()

        if len(active_threads) > 1:
          println("Threads lingering after test run:", ERROR)

          for lingering_thread in active_threads:
            println("  %s" % lingering_thread, ERROR)

          break
      except KeyboardInterrupt:
        println("  aborted starting tor: keyboard interrupt\n", ERROR)
        break
      except ValueError as exc:
        # can arise if get_torrc_entries() runs into a bad settings.cfg data

        println(str(exc), ERROR)
        break
      except OSError:
        error_tracker.register_error()
      finally:
        integ_runner.stop()

    if skipped_targets:
      println()

      for target in skipped_targets:
        req_version = test.util.get_prereq(target)
        println("Unable to run target %s, this requires tor version %s" % (target, req_version), ERROR)

      println()

  if not stem.prereq.is_python_3():
    _print_static_issues(args)

  runtime_label = "(%i seconds)" % (time.time() - start_time)

  if error_tracker.has_errors_occured():
    println("TESTING FAILED %s" % runtime_label, ERROR)

    for line in error_tracker:
      println("  %s" % line, ERROR)
  else:
    if skipped_tests > 0:
      println("%i TESTS WERE SKIPPED" % skipped_tests, STATUS)

    println("TESTING PASSED %s\n" % runtime_label, SUCCESS)

  sys.exit(1 if error_tracker.has_errors_occured() else 0)


def _get_args(argv):
  """
  Parses our arguments, providing a named tuple with their values.

  :param list argv: input arguments to be parsed

  :returns: a **named tuple** with our parsed arguments

  :raises: **ValueError** if we got an invalid argument
  :raises: **getopt.GetoptError** if the arguments don't conform with what we
    accept
  """

  args = dict(ARGS)

  for opt, arg in getopt.getopt(argv, OPT, OPT_EXPANDED)[0]:
    if opt in ("-a", "--all"):
      args['run_unit'] = True
      args['run_integ'] = True
      args['run_style'] = True
    elif opt in ("-u", "--unit"):
      args['run_unit'] = True
    elif opt in ("-i", "--integ"):
      args['run_integ'] = True
    elif opt in ("-s", "--style"):
      args['run_style'] = True
    elif opt == "--python3":
      args['run_python3'] = True
    elif opt == "--clean":
      args['run_python3_clean'] = True
    elif opt in ("-t", "--targets"):
      run_targets, attribute_targets = [], []

      integ_targets = arg.split(",")
      all_run_targets = [t for t in Target if CONFIG["target.torrc"].get(t) is not None]

      # validates the targets and split them into run and attribute targets

      if not integ_targets:
        raise ValueError("No targets provided")

      for target in integ_targets:
        if not target in Target:
          raise ValueError("Invalid integration target: %s" % target)
        elif target in all_run_targets:
          run_targets.append(target)
        else:
          attribute_targets.append(target)

      # check if we were told to use all run targets

      if Target.RUN_ALL in attribute_targets:
        attribute_targets.remove(Target.RUN_ALL)
        run_targets = all_run_targets

      args['run_targets'] = run_targets
      args['attribute_targets'] = attribute_targets
    elif opt in ("-l", "--test"):
      args['test_prefix'] = arg
    elif opt in ("-l", "--log"):
      arg = arg.upper()

      if not arg in stem.util.log.LOG_VALUES:
        raise ValueError(LOG_TYPE_ERROR % arg)

      args['logging_runlevel'] = arg
    elif opt in ("--tor"):
      args['tor_path'] = arg
    elif opt in ("-h", "--help"):
      args['print_help'] = True

  # translates our args dict into a named tuple

  Args = collections.namedtuple('Args', args.keys())
  return Args(**args)


def _print_static_issues(args):
  static_check_issues = {}

  # If we're doing some sort of testing (unit or integ) and pyflakes is
  # available then use it. Its static checks are pretty quick so there's not
  # much overhead in including it with all tests.

  if args.run_unit or args.run_integ:
    if stem.util.system.is_available("pyflakes"):
      static_check_issues.update(test.util.get_pyflakes_issues(SRC_PATHS))
    else:
      println("Static error checking requires pyflakes. Please install it from ...\n  http://pypi.python.org/pypi/pyflakes\n", ERROR)

  if args.run_style:
    if stem.util.system.is_available("pep8"):
      static_check_issues.update(test.util.get_stylistic_issues(SRC_PATHS))
    else:
      println("Style checks require pep8. Please install it from...\n  http://pypi.python.org/pypi/pep8\n", ERROR)

  if static_check_issues:
    println("STATIC CHECKS", STATUS)

    for file_path in static_check_issues:
      println("* %s" % file_path, STATUS)

      for line_number, msg in static_check_issues[file_path]:
        line_count = "%-4s" % line_number
        println("  line %s - %s" % (line_count, msg))

      println()


def _run_test(test_class, output_filters, logging_buffer):
  test.output.print_divider(test_class.__module__)
  suite = unittest.TestLoader().loadTestsFromTestCase(test_class)

  test_results = StringIO.StringIO()
  run_result = unittest.TextTestRunner(test_results, verbosity=2).run(suite)

  sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
  println()
  test.output.print_logging(logging_buffer)

  return run_result


if __name__ == '__main__':
  main()
