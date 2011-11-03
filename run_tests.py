#!/usr/bin/env python

"""
Runs unit and integration tests.
"""

import os
import sys
import time
import getopt
import unittest
import test.runner
import test.unit.message
import test.unit.version
import test.unit.types
import test.integ.message
import test.integ.system

from stem.util import enum, term

OPT = "uic:t:h"
OPT_EXPANDED = ["unit", "integ", "config=", "targets=", "help"]
DIVIDER = "=" * 70

# (name, class) tuples for all of our unit and integration tests
UNIT_TESTS = (("stem.types.ControlMessage", test.unit.message.TestMessageFunctions),
              ("stem.types.Version", test.unit.version.TestVerionFunctions),
              ("stem.types.get_entry", test.unit.types.TestGetEntry),
             )

INTEG_TESTS = (("stem.types.ControlMessage", test.integ.message.TestMessageFunctions),
               ("stem.util.system", test.integ.system.TestSystemFunctions),
              )

# TODO: drop targets?
# Configurations that the intergration tests can be ran with. Attributs are
# tuples of the test runner and description.
TARGETS = enum.Enum(*[(v, v) for v in ("NONE", "NO_CONTROL", "NO_AUTH", "COOKIE", "PASSWORD", "SOCKET")])
TARGET_ATTR = {
  TARGETS.NONE: (None, "No running tor instance."),
  TARGETS.NO_CONTROL: (None, "Basic client, no control port or socket."),
  TARGETS.NO_AUTH: (None, "Basic client, control port with no authenticaion."),
  TARGETS.COOKIE: (None, "Basic client, control port with cookie authenticaion."),
  TARGETS.PASSWORD: (None, "Basic client, control port wiht password authentication."),
  TARGETS.SOCKET: (None, "Basic client, control socket."),
}

HELP_MSG = """Usage runTests.py [OPTION]
Runs tests for the stem library.

  -u, --unit            runs unit tests
  -i, --integ           runs integration tests
  -c, --config PATH     path to a custom test configuration
  -t, --target TARGET   comma separated list of tor configurations to use for
                        the integration tests (all are used by default)
  -h, --help            presents this help

  Integration targets:
    %s
"""

if __name__ == '__main__':
  start_time = time.time()
  run_unit_tests = False
  run_integ_tests = False
  config_path = None
  integ_targets = TARGETS.values()
  
  # parses user input, noting any issues
  try:
    opts, args = getopt.getopt(sys.argv[1:], OPT, OPT_EXPANDED)
  except getopt.GetoptError, exc:
    print str(exc) + " (for usage provide --help)"
    sys.exit(1)
  
  for opt, arg in opts:
    if opt in ("-u", "--unit"): run_unit_tests = True
    elif opt in ("-i", "--integ"): run_integ_tests = True
    elif opt in ("-c", "--config"): config_path = arg
    elif opt in ("-t", "--targets"):
      integ_targets = arg.split(",")
      
      # validates the targets
      if not integ_targets:
        print "No targets provided"
        sys.exit(1)
      
      for target in integ_targets:
        if not target in TARGETS.values():
          print "Invalid integration target: %s" % target
          sys.exit(1)
    elif opt in ("-h", "--help"):
      # Prints usage information and quits. This includes a listing of the
      # valid integration targets.
      
      # gets the longest target length so we can show the entries in columns
      target_name_length = max([len(name) for name in TARGETS.values()])
      description_format = "%%-%is - %%s" % target_name_length
      
      target_lines = []
      for target in TARGETS.values():
        target_lines.append(description_format % (target, TARGET_ATTR[target][1]))
      
      print HELP_MSG % "\n    ".join(target_lines)
      sys.exit()
  
  if not run_unit_tests and not run_integ_tests:
    print "Nothing to run (for usage provide --help)\n"
    sys.exit()
  
  if run_unit_tests:
    print "%s\n%s\n%s\n" % (DIVIDER, "UNIT TESTS".center(70), DIVIDER)
    
    for name, test_class in UNIT_TESTS:
      print "%s\n%s\n%s\n" % (DIVIDER, name, DIVIDER)
      suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
      unittest.TextTestRunner(verbosity=2).run(suite)
      print
    
    print
  
  if run_integ_tests:
    print "%s\n%s\n%s\n" % (DIVIDER, "INTEGRATION TESTS".center(70), DIVIDER)
    
    integ_runner = test.runner.get_runner()
    
    try:
      # TODO: note unused config options afterward
      integ_runner.start(config_path = config_path)
      
      print term.format("Running tests...", term.Color.BLUE, term.Attr.BOLD)
      print
      
      for name, test_class in INTEG_TESTS:
        print "%s\n%s\n%s\n" % (DIVIDER, name, DIVIDER)
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        unittest.TextTestRunner(verbosity=2).run(suite)
        print
    except OSError:
      pass
    finally:
      integ_runner.stop()
    
    # TODO: we might do target selection later but for now we should simply
    # work with a single simple tor instance and see how it works out
    #
    #for target in integ_targets:
    #  runner, description = TARGET_ATTR[target]
    #  
    #  print "Configuration: %s - %s" % (target, description)
    #  
    #  if runner:
    #    pass # TODO: implement
    #  else:
    #    print "  %s" % term.format("Unimplemented", term.Color.RED, term.Attr.BOLD)
    #  
    #  print ""
  
  print term.format("Testing Completed (%i seconds)" % (time.time() - start_time), term.Color.GREEN, term.Attr.BOLD)
  print

