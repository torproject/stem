#!/usr/bin/env python

"""
Runs unit and integration tests.
"""

import os
import sys
import time
import getopt
import signal
import tempfile
import unittest
import subprocess
import test.unit.message
import test.unit.version

from stem.util import enum, system, term

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

# Number of seconds before we time out our attempt to start a tor instance
TOR_INIT_TIMEOUT = 20

def init_tor_process(torrc_dst):
  """
  Initializes and returns a tor process. This blocks until initialization
  completes or we error out.
  
  Arguments:
    torrc_dst (str) - path for a torrc configuration to use
  
  Returns:
    subprocess.Popen instance for the instantiated tor process
  
  Raises:
    OSError if we either fail to create the tor process or reached a timeout without success
  """
  
  start_time = time.time()
  
  # starts a tor subprocess, raising an OSError if it fails
  tor_process = subprocess.Popen(["tor", "-f", torrc_dst], stdout = subprocess.PIPE, stderr = subprocess.PIPE)
  
  # time ourselves out if we reach TOR_INIT_TIMEOUT
  def timeout_handler(signum, frame):
    # terminates the uninitialized tor process and raise on timeout
    tor_process.kill()
    raise OSError("unable to start tor: reached a %i second timeout without success" % TOR_INIT_TIMEOUT)
  
  signal.signal(signal.SIGALRM, timeout_handler)
  signal.alarm(TOR_INIT_TIMEOUT)
  
  print term.format("Starting tor...", term.Color.BLUE, term.Attr.BOLD)
  
  while True:
    init_line = tor_process.stdout.readline().strip()
    
    # this will provide empty results if the process is terminated
    if not init_line:
      tor_process.kill() # ... but best make sure
      raise OSError("tor process terminated")
    
    print term.format("  %s" % init_line, term.Color.BLUE)
    
    # return the process if we're done with bootstrapping
    if init_line.endswith("Bootstrapped 100%: Done."):
      print term.format("  done (%i seconds)" % (time.time() - start_time), term.Color.BLUE, term.Attr.BOLD)
      print
      
      return tor_process

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
      suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
      unittest.TextTestRunner(verbosity=2).run(suite)
      print
    
    print
  
  if run_integ_tests:
    # TODO: check if there's already a tor instance running
    
    print "%s\n%s\n%s\n" % (DIVIDER, "INTEGRATION TESTS".center(70), DIVIDER)
    
    print term.format("Setting up a test instance...", term.Color.BLUE, term.Attr.BOLD)
    
    # makes a temporary directory for the runtime resources of our integ test
    test_dir = tempfile.mktemp("-stem-integ")
    
    try:
      os.makedirs(test_dir)
      print term.format("  created test directory: %s" % test_dir, term.Color.BLUE, term.Attr.BOLD)
    except OSError, exc:
      print term.format("Unable to make testing directory: %s" % exc, term.Color.RED, term.Attr.BOLD)
      sys.exit(1)
    
    # makes a basic torrc for the integration tests to run against
    torrc_contents = """# basic integration testing configuration
DataDirectory %s
ControlPort 9051
""" % test_dir
    
    # writes our testing torrc
    torrc_dst = os.path.join(test_dir, "torrc")
    try:
      torrc_file = open(torrc_dst, "w")
      torrc_file.write(torrc_contents)
      torrc_file.close()
      
      print term.format("  wrote torrc: %s" % torrc_dst, term.Color.BLUE, term.Attr.BOLD)
      
      for line in torrc_contents.split("\n"):
        print term.format("    %s" % line.strip(), term.Color.BLUE)
    except Exception, exc:
      print term.format("Unable to write testing torrc: %s" % exc, term.Color.RED, term.Attr.BOLD)
      sys.exit(1)
    
    # starts a tor instance
    try:
      tor_process = init_tor_process(torrc_dst)
    except OSError, exc:
      print term.format("Unable to start a tor instance: %s" % exc, term.Color.RED, term.Attr.BOLD)
      sys.exit(1)
      
    print term.format("Running tests...", term.Color.BLUE, term.Attr.BOLD)
    print
    
    # TODO: run tests
    
    print term.format("Shutting down tor...", term.Color.BLUE, term.Attr.BOLD)
    tor_process.kill()
    print term.format("  done", term.Color.BLUE, term.Attr.BOLD)
    
    
    
    
    
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

