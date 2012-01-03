#!/usr/bin/env python

"""
Runs unit and integration tests.
"""

import os
import sys
import time
import getopt
import logging
import unittest
import StringIO

import test.output
import test.runner
import test.unit.connection.authentication
import test.unit.connection.protocolinfo
import test.unit.socket.control_line
import test.unit.socket.control_message
import test.unit.util.enum
import test.unit.util.system
import test.unit.version
import test.integ.connection.authentication
import test.integ.connection.connect
import test.integ.connection.protocolinfo
import test.integ.socket.control_message
import test.integ.util.conf
import test.integ.util.system
import test.integ.version

import stem.util.enum
import stem.util.log as log
import stem.util.term as term

OPT = "uic:t:l:h"
OPT_EXPANDED = ["unit", "integ", "config=", "targets=", "log=", "help"]
DIVIDER = "=" * 70

# Tests are ordered by the dependencies so the lowest level tests come first.
# This is because a problem in say, controller message parsing, will cause all
# higher level tests to fail too. Hence we want the test that most narrowly
# exhibits problems to come first.

UNIT_TESTS = (
  test.unit.util.enum.TestEnum,
  test.unit.util.system.TestSystem,
  test.unit.version.TestVersion,
  test.unit.socket.control_message.TestControlMessage,
  test.unit.socket.control_line.TestControlLine,
  test.unit.connection.authentication.TestAuthenticate,
  test.unit.connection.protocolinfo.TestProtocolInfoResponse,
)

INTEG_TESTS = (
  test.integ.util.conf.TestConf,
  test.integ.util.system.TestSystem,
  test.integ.version.TestVersion,
  test.integ.socket.control_message.TestControlMessage,
  test.integ.connection.protocolinfo.TestProtocolInfo,
  test.integ.connection.authentication.TestAuthenticate,
  test.integ.connection.connect.TestConnect,
)

# Integration tests above the basic suite.
TARGETS = stem.util.enum.Enum(*[(v, v) for v in ("ONLINE", "RELATIVE", "CONN_NONE", "CONN_OPEN", "CONN_PASSWORD", "CONN_COOKIE", "CONN_MULTIPLE", "CONN_SOCKET", "CONN_SCOOKIE", "CONN_ALL")])

TARGET_ATTR = {
  TARGETS.ONLINE: ("test.integ.target.online", "Includes tests that require network activity."),
  TARGETS.RELATIVE: ("test.integ.target.relative_data_dir", "Uses a relative path for tor's data directory."),
  TARGETS.CONN_NONE: ("test.integ.target.connection.none", "Configuration without a way for controllers to connect."),
  TARGETS.CONN_OPEN: ("test.integ.target.connection.open", "Configuration with an open control port (default)."),
  TARGETS.CONN_PASSWORD: ("test.integ.target.connection.password", "Configuration with password authentication."),
  TARGETS.CONN_COOKIE: ("test.integ.target.connection.cookie", "Configuration with an authentication cookie."),
  TARGETS.CONN_MULTIPLE: ("test.integ.target.connection.multiple", "Configuration with both password and cookie authentication."),
  TARGETS.CONN_SOCKET: ("test.integ.target.connection.socket", "Configuration with a control socket."),
  TARGETS.CONN_SCOOKIE: ("test.integ.target.connection.scookie", "Configuration with a control socket and authentication cookie."),
  TARGETS.CONN_ALL: ("test.integ.target.connection.all", "Runs integration tests for all connection configurations."),
}

HELP_MSG = """Usage runTests.py [OPTION]
Runs tests for the stem library.

  -u, --unit            runs unit tests
  -i, --integ           runs integration tests
  -c, --config PATH     path to a custom test configuration
  -t, --target TARGET   comma separated list of extra targets for integ tests
  -l, --log RUNLEVEL    includes logging output with test results, runlevels:
                          TRACE, DEBUG, INFO, NOTICE, WARN, ERROR
  -h, --help            presents this help

  Integration targets:
    %s
"""

# TODO: add an option to disable output coloring?

HEADER_ATTR = (term.Color.CYAN, term.Attr.BOLD)
CATEGORY_ATTR = (term.Color.GREEN, term.Attr.BOLD)
DEFAULT_TEST_ATTR = (term.Color.CYAN,)

TEST_OUTPUT_ATTR = {
  "... ok": (term.Color.GREEN,),
  "... FAIL": (term.Color.RED, term.Attr.BOLD),
  "... ERROR": (term.Color.RED, term.Attr.BOLD),
  "... skipped": (term.Color.BLUE,),
}

def print_divider(msg, is_header = False):
  attr = HEADER_ATTR if is_header else CATEGORY_ATTR
  print term.format("%s\n%s\n%s\n" % (DIVIDER, msg.center(70), DIVIDER), *attr)

def print_logging(logging_buffer):
  if not logging_buffer.is_empty():
    for line in logging_buffer:
      print term.format(line, term.Color.MAGENTA)
    
    print

if __name__ == '__main__':
  start_time = time.time()
  run_unit_tests = False
  run_integ_tests = False
  config_path = None
  test_config = stem.util.conf.get_config("test")
  logging_runlevel = None
  
  # parses user input, noting any issues
  try:
    opts, args = getopt.getopt(sys.argv[1:], OPT, OPT_EXPANDED)
  except getopt.GetoptError, exc:
    print str(exc) + " (for usage provide --help)"
    sys.exit(1)
  
  for opt, arg in opts:
    if opt in ("-u", "--unit"): run_unit_tests = True
    elif opt in ("-i", "--integ"): run_integ_tests = True
    elif opt in ("-c", "--config"): config_path = os.path.abspath(arg)
    elif opt in ("-t", "--targets"):
      integ_targets = arg.split(",")
      
      # validates the targets
      if not integ_targets:
        print "No targets provided"
        sys.exit(1)
      
      for target in integ_targets:
        if not target in TARGETS:
          print "Invalid integration target: %s" % target
          sys.exit(1)
        else:
          # sets the configuration flag
          config_flag = TARGET_ATTR[target][0]
          test_config.set(config_flag, "true")
    elif opt in ("-l", "--log"):
      logging_runlevel = arg.upper()
      
      if not logging_runlevel in log.LOG_VALUES:
        print "'%s' isn't a logging runlevel, use one of the following instead:" % arg
        print "  TRACE, DEBUG, INFO, NOTICE, WARN, ERROR"
        sys.exit(1)
    elif opt in ("-h", "--help"):
      # Prints usage information and quits. This includes a listing of the
      # valid integration targets.
      
      # gets the longest target length so we can show the entries in columns
      target_name_length = max([len(name) for name in TARGETS])
      description_format = "%%-%is - %%s" % target_name_length
      
      target_lines = []
      for target in TARGETS:
        target_lines.append(description_format % (target, TARGET_ATTR[target][1]))
      
      print HELP_MSG % "\n    ".join(target_lines)
      sys.exit()
  
  if not run_unit_tests and not run_integ_tests:
    print "Nothing to run (for usage provide --help)\n"
    sys.exit()
  
  if config_path:
    print_divider("TESTING CONFIG", True)
    print
    
    try:
      sys.stdout.write(term.format("Loading test configuration (%s)... " % config_path, term.Color.BLUE, term.Attr.BOLD))
      test_config.load(config_path)
      sys.stdout.write(term.format("done\n", term.Color.BLUE, term.Attr.BOLD))
      
      for config_key in test_config.keys():
        key_entry = "  %s => " % config_key
        
        # if there's multiple values then list them on separate lines
        value_div = ",\n" + (" " * len(key_entry))
        value_entry = value_div.join(test_config.get_value(config_key, multiple = True))
        
        sys.stdout.write(term.format(key_entry + value_entry + "\n", term.Color.BLUE))
    except IOError, exc:
      sys.stdout.write(term.format("failed (%s)\n" % exc, term.Color.RED, term.Attr.BOLD))
    
    print
  
  error_tracker = test.output.ErrorTracker()
  output_filters = (
    error_tracker.get_filter(),
    test.output.strip_module,
    test.output.align_results,
    test.output.colorize,
  )
  
  stem_logger = logging.getLogger("stem")
  logging_buffer = test.output.LogBuffer(log.logging_level(logging_runlevel))
  stem_logger.addHandler(logging_buffer)
  stem_logger.setLevel(logging.DEBUG)
  
  if run_unit_tests:
    print_divider("UNIT TESTS", True)
    
    for test_class in UNIT_TESTS:
      print_divider(test_class.__module__)
      suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
      test_results = StringIO.StringIO()
      unittest.TextTestRunner(test_results, verbosity=2).run(suite)
      
      sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
      print
      
      print_logging(logging_buffer)
    
    print
  
  if run_integ_tests:
    print_divider("INTEGRATION TESTS", True)
    integ_runner = test.runner.get_runner()
    
    # queue up all of the tor configurations we want to run the integration
    # tests on
    
    connection_types = []
    
    if test_config.get("test.integ.target.connection.all", False):
      connection_types = list(test.runner.TorConnection)
    else:
      # mapping of config type to (enum, default) tuple
      conn_type_mappings = {
        "none": test.runner.TorConnection.NONE,
        "open": test.runner.TorConnection.OPEN,
        "password": test.runner.TorConnection.PASSWORD,
        "cookie": test.runner.TorConnection.COOKIE,
        "multiple": test.runner.TorConnection.MULTIPLE,
        "socket": test.runner.TorConnection.SOCKET,
        "scookie": test.runner.TorConnection.SCOOKIE,
      }
      
      for type_key in conn_type_mappings:
        if test_config.get("test.integ.target.connection.%s" % type_key, False):
          connection_types.append(conn_type_mappings[type_key])
    
    # TorConnection.OPEN is the default if we don't have any defined
    if not connection_types:
      connection_types = [test.runner.TorConnection.OPEN]
    
    for connection_type in connection_types:
      try:
        integ_runner.start(connection_type = connection_type)
        
        print term.format("Running tests...", term.Color.BLUE, term.Attr.BOLD)
        print
        
        for test_class in INTEG_TESTS:
          print_divider(test_class.__module__)
          stem_logger.info("STARTING INTEGRATION TEST => %s" % test_class.__module__)
          suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
          test_results = StringIO.StringIO()
          unittest.TextTestRunner(test_results, verbosity=2).run(suite)
          
          sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
          print
          
          print_logging(logging_buffer)
      except OSError:
        pass
      finally:
        integ_runner.stop()
    
    # TODO: note unused config options afterward?
  
  runtime_label = "(%i seconds)" % (time.time() - start_time)
  
  if error_tracker.has_error_occured():
    print term.format("TESTING FAILED %s" % runtime_label, term.Color.RED, term.Attr.BOLD)
    
    for line in error_tracker:
      print term.format("  %s" % line, term.Color.RED, term.Attr.BOLD)
  else:
    print term.format("TESTING PASSED %s" % runtime_label, term.Color.GREEN, term.Attr.BOLD)
    print

