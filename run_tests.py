#!/usr/bin/env python
# Copyright 2011-2013, Damian Johnson
# See LICENSE for licensing information

"""
Runs unit and integration tests. For usage information run this with '--help'.
"""

import getopt
import os
import shutil
import StringIO
import sys
import threading
import time
import unittest

import stem.prereq
import stem.util.conf
import stem.util.enum

from stem.util import log, system

import test.output
import test.runner
import test.util

from test.output import println, STATUS, SUCCESS, ERROR, NO_NL
from test.runner import Target

OPT = "auist:l:h"
OPT_EXPANDED = ["all", "unit", "integ", "style", "python3", "clean", "targets=", "test=", "log=", "tor=", "help"]

CONFIG = stem.util.conf.config_dict("test", {
  "msg.help": "",
  "target.description": {},
  "target.prereq": {},
  "target.torrc": {},
  "integ.test_directory": "./test/data",
})

DEFAULT_RUN_TARGET = Target.RUN_OPEN

base = os.path.sep.join(__file__.split(os.path.sep)[:-1]).lstrip("./")
SOURCE_BASE_PATHS = [os.path.join(base, path) for path in ('stem', 'test', 'run_tests.py')]


def _python3_setup(python3_destination, clean):
  """
  Exports the python3 counterpart of our codebase using 2to3.

  :param str python3_destination: location to export our codebase to
  :param bool clean: deletes our priorly exported codebase if **True**,
    otherwise this is a no-op
  """

  # Python 2.7.3 added some nice capabilities to 2to3, like '--output-dir'...
  #
  #   http://docs.python.org/2/library/2to3.html
  #
  # ... but I'm using 2.7.1, and it's pretty easy to make it work without
  # requiring a bleeding edge interpretor.

  test.output.print_divider("EXPORTING TO PYTHON 3", True)

  if clean:
    shutil.rmtree(python3_destination, ignore_errors = True)

  if os.path.exists(python3_destination):
    println("Reusing '%s'. Run again with '--clean' if you want to recreate the python3 export.\n" % python3_destination, ERROR)
    return True

  os.makedirs(python3_destination)

  try:
    # skips the python3 destination (to avoid an infinite loop)
    def _ignore(src, names):
      if src == os.path.normpath(python3_destination):
        return names
      else:
        return []

    println("  copying stem to '%s'... " % python3_destination, STATUS, NO_NL)
    shutil.copytree('stem', os.path.join(python3_destination, 'stem'))
    shutil.copytree('test', os.path.join(python3_destination, 'test'), ignore = _ignore)
    shutil.copy('run_tests.py', os.path.join(python3_destination, 'run_tests.py'))
    println("done", STATUS)
  except OSError, exc:
    println("failed\n%s" % exc, ERROR)
    return False

  try:
    println("  running 2to3... ", STATUS, NO_NL)
    system.call("2to3 --write --nobackups --no-diffs %s" % python3_destination)
    println("done", STATUS)
  except OSError, exc:
    println("failed\n%s" % exc, ERROR)
    return False

  return True


def _print_static_issues(run_unit, run_integ, run_style):
  static_check_issues = {}

  # If we're doing some sort of testing (unit or integ) and pyflakes is
  # available then use it. Its static checks are pretty quick so there's not
  # much overhead in including it with all tests.

  if run_unit or run_integ:
    if system.is_available("pyflakes"):
      static_check_issues.update(test.util.get_pyflakes_issues(SOURCE_BASE_PATHS))
    else:
      println("Static error checking requires pyflakes. Please install it from ...\n  http://pypi.python.org/pypi/pyflakes\n", ERROR)

  if run_style:
    if system.is_available("pep8"):
      static_check_issues = test.util.get_stylistic_issues(SOURCE_BASE_PATHS)
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


if __name__ == '__main__':
  try:
    stem.prereq.check_requirements()
  except ImportError, exc:
    println("%s\n" % exc)
    sys.exit(1)

  start_time = time.time()

  # override flag to indicate at the end that testing failed somewhere
  testing_failed = False

  # count how many tests have been skipped.
  skipped_test_count = 0

  # loads and validates our various configurations
  test_config = stem.util.conf.get_config("test")

  settings_path = os.path.join(test.runner.STEM_BASE, "test", "settings.cfg")
  test_config.load(settings_path)

  try:
    opts = getopt.getopt(sys.argv[1:], OPT, OPT_EXPANDED)[0]
  except getopt.GetoptError, exc:
    println("%s (for usage provide --help)" % exc)
    sys.exit(1)

  run_unit = False
  run_integ = False
  run_style = False
  run_python3 = False
  run_python3_clean = False

  test_prefix = None
  logging_runlevel = None
  tor_path = "tor"

  # Integration testing targets fall into two categories:
  #
  # * Run Targets (like RUN_COOKIE and RUN_PTRACE) which customize our torrc.
  #   We do an integration test run for each run target we get.
  #
  # * Attribute Target (like CHROOT and ONLINE) which indicates
  #   non-configuration changes to ur test runs. These are applied to all
  #   integration runs that we perform.

  run_targets = [DEFAULT_RUN_TARGET]
  attribute_targets = []

  for opt, arg in opts:
    if opt in ("-a", "--all"):
      run_unit = True
      run_integ = True
      run_style = True
    elif opt in ("-u", "--unit"):
      run_unit = True
    elif opt in ("-i", "--integ"):
      run_integ = True
    elif opt in ("-s", "--style"):
      run_style = True
    elif opt == "--python3":
      run_python3 = True
    elif opt == "--clean":
      run_python3_clean = True
    elif opt in ("-t", "--targets"):
      integ_targets = arg.split(",")

      run_targets = []
      all_run_targets = [t for t in Target if CONFIG["target.torrc"].get(t) is not None]

      # validates the targets and split them into run and attribute targets

      if not integ_targets:
        println("No targets provided")
        sys.exit(1)

      for target in integ_targets:
        if not target in Target:
          println("Invalid integration target: %s" % target)
          sys.exit(1)
        elif target in all_run_targets:
          run_targets.append(target)
        else:
          attribute_targets.append(target)

      # check if we were told to use all run targets

      if Target.RUN_ALL in attribute_targets:
        attribute_targets.remove(Target.RUN_ALL)
        run_targets = all_run_targets
    elif opt in ("-l", "--test"):
      test_prefix = arg
    elif opt in ("-l", "--log"):
      logging_runlevel = arg.upper()
    elif opt in ("--tor"):
      tor_path = arg
    elif opt in ("-h", "--help"):
      # Prints usage information and quits. This includes a listing of the
      # valid integration targets.

      println(CONFIG["msg.help"])

      # gets the longest target length so we can show the entries in columns
      target_name_length = max(map(len, Target))
      description_format = "    %%-%is - %%s" % target_name_length

      for target in Target:
        println(description_format % (target, CONFIG["target.description"].get(target, "")))

      println()
      sys.exit()

  # basic validation on user input

  if logging_runlevel and not logging_runlevel in log.LOG_VALUES:
    println("'%s' isn't a logging runlevel, use one of the following instead:" % logging_runlevel)
    println("  TRACE, DEBUG, INFO, NOTICE, WARN, ERROR")
    sys.exit(1)

  # check that we have 2to3 and python3 available in our PATH
  if run_python3:
    for required_cmd in ("2to3", "python3"):
      if not system.is_available(required_cmd):
        println("Unable to test python 3 because %s isn't in your path" % required_cmd, ERROR)
        sys.exit(1)

  if run_python3 and sys.version_info[0] != 3:
    python3_destination = os.path.join(CONFIG["integ.test_directory"], "python3")

    if _python3_setup(python3_destination, run_python3_clean):
      python3_runner = os.path.join(python3_destination, "run_tests.py")
      exit_status = os.system("python3 %s %s" % (python3_runner, " ".join(sys.argv[1:])))
      sys.exit(exit_status)
    else:
      sys.exit(1)  # failed to do python3 setup

  if not run_unit and not run_integ and not run_style:
    println("Nothing to run (for usage provide --help)\n")
    sys.exit()

  # if we have verbose logging then provide the testing config
  our_level = stem.util.log.logging_level(logging_runlevel)
  info_level = stem.util.log.logging_level(stem.util.log.INFO)

  if our_level <= info_level:
    test.output.print_config(test_config)

  error_tracker = test.output.ErrorTracker()
  output_filters = (
    error_tracker.get_filter(),
    test.output.strip_module,
    test.output.align_results,
    test.output.colorize,
  )

  stem_logger = log.get_logger()
  logging_buffer = log.LogBuffer(logging_runlevel)
  stem_logger.addHandler(logging_buffer)

  test.output.print_divider("INITIALISING", True)

  println("Performing startup activities...", STATUS)
  println("  checking for orphaned .pyc files... ", STATUS, NO_NL)

  orphaned_pyc = test.util.clean_orphaned_pyc(SOURCE_BASE_PATHS)

  if not orphaned_pyc:
    # no orphaned files, nothing to do
    println("done", STATUS)
  else:
    println()
    for pyc_file in orphaned_pyc:
      println("    removed %s" % pyc_file, ERROR)

  println()

  if run_unit:
    test.output.print_divider("UNIT TESTS", True)
    error_tracker.set_category("UNIT TEST")

    for test_class in test.util.get_unit_tests(test_prefix):
      test.output.print_divider(test_class.__module__)
      suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
      test_results = StringIO.StringIO()
      run_result = unittest.TextTestRunner(test_results, verbosity=2).run(suite)
      if stem.prereq.is_python_27():
        skipped_test_count += len(run_result.skipped)

      sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
      println()

      test.output.print_logging(logging_buffer)

    println()

  if run_integ:
    test.output.print_divider("INTEGRATION TESTS", True)
    integ_runner = test.runner.get_runner()

    # Determine targets we don't meet the prereqs for. Warnings are given about
    # these at the end of the test run so they're more noticeable.

    our_version = stem.version.get_system_tor_version(tor_path)
    skip_targets = []

    for target in run_targets:
      # check if we meet this target's tor version prerequisites

      target_prereq = CONFIG["target.prereq"].get(target)

      if target_prereq and our_version < stem.version.Requirement[target_prereq]:
        skip_targets.append(target)
        continue

      error_tracker.set_category(target)

      try:
        # converts the 'target.torrc' csv into a list of test.runner.Torrc enums
        config_csv = CONFIG["target.torrc"].get(target)
        torrc_opts = []

        if config_csv:
          for opt in config_csv.split(','):
            opt = opt.strip()

            if opt in test.runner.Torrc.keys():
              torrc_opts.append(test.runner.Torrc[opt])
            else:
              println("'%s' isn't a test.runner.Torrc enumeration" % opt)
              sys.exit(1)

        integ_runner.start(target, attribute_targets, tor_path, extra_torrc_opts = torrc_opts)

        println("Running tests...\n", STATUS)

        for test_class in test.util.get_integ_tests(test_prefix):
          test.output.print_divider(test_class.__module__)
          suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
          test_results = StringIO.StringIO()
          run_result = unittest.TextTestRunner(test_results, verbosity=2).run(suite)
          if stem.prereq.is_python_27():
            skipped_test_count += len(run_result.skipped)

          sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
          println()

          test.output.print_logging(logging_buffer)

        # We should have joined on all threads. If not then that indicates a
        # leak that could both likely be a bug and disrupt further targets.

        active_threads = threading.enumerate()

        if len(active_threads) > 1:
          println("Threads lingering after test run:", ERROR)

          for lingering_thread in active_threads:
            println("  %s" % lingering_thread, ERROR)

          testing_failed = True
          break
      except KeyboardInterrupt:
        println("  aborted starting tor: keyboard interrupt\n", ERROR)
        break
      except OSError:
        testing_failed = True
      finally:
        integ_runner.stop()

    if skip_targets:
      println()

      for target in skip_targets:
        req_version = stem.version.Requirement[CONFIG["target.prereq"][target]]
        println("Unable to run target %s, this requires tor version %s" % (target, req_version), ERROR)

      println()

    # TODO: note unused config options afterward?

  if not stem.prereq.is_python_3():
    _print_static_issues(run_unit, run_integ, run_style)

  runtime = time.time() - start_time

  if runtime < 1:
    runtime_label = "(%0.1f seconds)" % runtime
  else:
    runtime_label = "(%i seconds)" % runtime

  has_error = testing_failed or error_tracker.has_error_occured()

  if has_error:
    println("TESTING FAILED %s" % runtime_label, ERROR)

    for line in error_tracker:
      println("  %s" % line, ERROR)
  elif skipped_test_count > 0:
    println("%i TESTS WERE SKIPPED" % skipped_test_count, STATUS)
    println("ALL OTHER TESTS PASSED %s\n" % runtime_label, SUCCESS)
  else:
    println("TESTING PASSED %s\n" % runtime_label, SUCCESS)

  sys.exit(1 if has_error else 0)
