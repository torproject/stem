#!/usr/bin/env python

"""
Runs unit and integration tests.
"""

import sys
import getopt
import unittest
import test.unit.message
import test.unit.version

from stem.util import enum, term

OPT = "uit:h"
OPT_EXPANDED = ["unit", "integ", "targets=", "help"]
DIVIDER = "=" * 70

# (name, class) tuples for all of our unit tests
UNIT_TESTS = (("stem.types.ControlMessage", test.unit.message.TestMessageFunctions),
              ("stem.types.Version", test.unit.version.TestVerionFunctions),
             )

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

  -u, --unit      runs unit tests
  -i, --integ     runs integration tests
  -t, --target    comma separated list of tor configurations to use for the
                    integration tests (all are used by default)
  -h, --help      presents this help

  Integration targets:
    %s
"""

if __name__ == '__main__':
  run_unit_tests = False
  run_integ_tests = False
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
      #print name
      suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
      unittest.TextTestRunner(verbosity=2).run(suite)
      print
    
    #import test.unit
    #suite = unittest.TestLoader().loadTestsFromTestCase(test.unit.version.TestVerionFunctions)
    #suite = unittest.TestLoader().discover("test/unit/", "*.py")
    #suite.addTests(unittest.loader.loadTestsFromTestCase(test.unit.message.TestMessageFunctions))
    
    #suite = unittest.TestLoader()
    #suite.loadTestsFromTestCase(test.unit.message.TestMessageFunctions)
    #suite.loadTestsFromTestCase(test.unit.version.TestVerionFunctions)
    #unittest.TextTestRunner(verbosity=2).run(suite)
    
    print
  
  if run_integ_tests:
    print "%s\n%s\n%s\n" % (DIVIDER, "INTEGRATION TESTS".center(70), DIVIDER)
    
    for target in integ_targets:
      runner, description = TARGET_ATTR[target]
      
      print "Configuration: %s - %s" % (target, description)
      
      if runner:
        pass # TODO: implement
      else:
        print "  %s" % term.format("Unimplemented", term.Color.RED, term.Attr.BOLD)
      
      print ""

