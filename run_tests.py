#!/usr/bin/env python

"""
Runs unit and integration tests. For usage information run this with '--help'.
"""

import os
import sys
import time
import getopt
import unittest
import threading
import StringIO

import test.output
import test.runner
import test.check_whitespace
import test.unit.connection.authentication
import test.unit.descriptor.reader
import test.unit.descriptor.server_descriptor
import test.unit.descriptor.extrainfo_descriptor
import test.unit.response.control_line
import test.unit.response.control_message
import test.unit.response.getinfo
import test.unit.response.protocolinfo
import test.unit.response.authchallenge
import test.unit.util.conf
import test.unit.util.connection
import test.unit.util.enum
import test.unit.util.system
import test.unit.util.tor_tools
import test.unit.util.proc
import test.unit.version
import test.integ.connection.authentication
import test.integ.connection.connect
import test.integ.control.base_controller
import test.integ.control.controller
import test.integ.socket.control_message
import test.integ.socket.control_socket
import test.integ.descriptor.reader
import test.integ.descriptor.server_descriptor
import test.integ.descriptor.extrainfo_descriptor
import test.integ.response.protocolinfo
import test.integ.util.conf
import test.integ.util.system
import test.integ.util.proc
import test.integ.process
import test.integ.version

import stem.prereq
import stem.util.conf
import stem.util.enum
import stem.util.log as log
import stem.util.term as term
import stem.util.system as system

OPT = "uit:l:c:h"
OPT_EXPANDED = ["unit", "integ", "targets=", "test=", "log=", "tor=", "config=", "help"]
DIVIDER = "=" * 70

CONFIG = stem.util.conf.config_dict("test", {
  "argument.unit": False,
  "argument.integ": False,
  "argument.test": "",
  "argument.log": None,
  "argument.tor": "tor",
  "argument.no_color": False,
  "msg.help": "",
  "target.config": {},
  "target.description": {},
  "target.prereq": {},
  "target.torrc": {},
})

Target = stem.util.enum.UppercaseEnum(
  "ONLINE",
  "RELATIVE",
  "CHROOT",
  "RUN_NONE",
  "RUN_OPEN",
  "RUN_PASSWORD",
  "RUN_COOKIE",
  "RUN_MULTIPLE",
  "RUN_SOCKET",
  "RUN_SCOOKIE",
  "RUN_PTRACE",
  "RUN_ALL",
)

DEFAULT_RUN_TARGET = Target.RUN_OPEN

ERROR_ATTR = (term.Color.RED, term.Attr.BOLD)

# Tests are ordered by the dependencies so the lowest level tests come first.
# This is because a problem in say, controller message parsing, will cause all
# higher level tests to fail too. Hence we want the test that most narrowly
# exhibits problems to come first.

UNIT_TESTS = (
  test.unit.util.enum.TestEnum,
  test.unit.util.connection.TestConnection,
  test.unit.util.conf.TestConf,
  test.unit.util.proc.TestProc,
  test.unit.util.system.TestSystem,
  test.unit.util.tor_tools.TestTorTools,
  test.unit.descriptor.reader.TestDescriptorReader,
  test.unit.descriptor.server_descriptor.TestServerDescriptor,
  test.unit.descriptor.extrainfo_descriptor.TestExtraInfoDescriptor,
  test.unit.version.TestVersion,
  test.unit.response.control_message.TestControlMessage,
  test.unit.response.control_line.TestControlLine,
  test.unit.response.getinfo.TestGetInfoResponse,
  test.unit.response.protocolinfo.TestProtocolInfoResponse,
  test.unit.response.authchallenge.TestAuthChallengeResponse,
  test.unit.connection.authentication.TestAuthenticate,
)

INTEG_TESTS = (
  test.integ.util.conf.TestConf,
  test.integ.util.proc.TestProc,
  test.integ.util.system.TestSystem,
  test.integ.descriptor.reader.TestDescriptorReader,
  test.integ.descriptor.server_descriptor.TestServerDescriptor,
  test.integ.descriptor.extrainfo_descriptor.TestExtraInfoDescriptor,
  test.integ.version.TestVersion,
  test.integ.response.protocolinfo.TestProtocolInfo,
  test.integ.process.TestProcess,
  test.integ.socket.control_socket.TestControlSocket,
  test.integ.socket.control_message.TestControlMessage,
  test.integ.connection.authentication.TestAuthenticate,
  test.integ.connection.connect.TestConnect,
  test.integ.control.base_controller.TestBaseController,
  test.integ.control.controller.TestController,
)

def load_user_configuration(test_config):
  """
  Parses our commandline arguments, loading our custom test configuration if
  '--config' was provided and then appending arguments to that. This does some
  sanity checking on the input, printing an error and quitting if validation
  fails.
  """
  
  arg_overrides, config_path = {}, None
  
  try:
    opts, args = getopt.getopt(sys.argv[1:], OPT, OPT_EXPANDED)
  except getopt.GetoptError, exc:
    print "%s (for usage provide --help)" % exc
    sys.exit(1)
  
  # suppress color output if our output is being piped
  if (not sys.stdout.isatty()) or system.is_windows():
    arg_overrides["argument.no_color"] = "true"
  
  for opt, arg in opts:
    if opt in ("-u", "--unit"):
      arg_overrides["argument.unit"] = "true"
    elif opt in ("-i", "--integ"):
      arg_overrides["argument.integ"] = "true"
    elif opt in ("-c", "--config"):
      config_path = os.path.abspath(arg)
    elif opt in ("-t", "--targets"):
      integ_targets = arg.split(",")
      
      # validates the targets
      if not integ_targets:
        print "No targets provided"
        sys.exit(1)
      
      for target in integ_targets:
        if not target in Target:
          print "Invalid integration target: %s" % target
          sys.exit(1)
        else:
          target_config = test_config.get("target.config", {}).get(target)
          if target_config: arg_overrides[target_config] = "true"
    elif opt in ("-l", "--test"):
      arg_overrides["argument.test"] = arg
    elif opt in ("-l", "--log"):
      arg_overrides["argument.log"] = arg.upper()
    elif opt in ("--tor"):
      arg_overrides["argument.tor"] = arg
    elif opt in ("-h", "--help"):
      # Prints usage information and quits. This includes a listing of the
      # valid integration targets.
      
      print CONFIG["msg.help"]
      
      # gets the longest target length so we can show the entries in columns
      target_name_length = max(map(len, Target))
      description_format = "    %%-%is - %%s" % target_name_length
      
      for target in Target:
        print description_format % (target, CONFIG["target.description"].get(target, ""))
      
      print
      
      sys.exit()
  
  # load a testrc if '--config' was given, then apply arguments
  
  if config_path:
    try:
      test_config.load(config_path)
    except IOError, exc:
      print "Unable to load testing configuration at '%s': %s" % (config_path, exc)
      sys.exit(1)
  
  for key, value in arg_overrides.items():
    test_config.set(key, value)
  
  # basic validation on user input
  
  log_config = CONFIG["argument.log"]
  if log_config and not log_config in log.LOG_VALUES:
    print "'%s' isn't a logging runlevel, use one of the following instead:" % log_config
    print "  TRACE, DEBUG, INFO, NOTICE, WARN, ERROR"
    sys.exit(1)
  
  tor_config = CONFIG["argument.tor"]
  if CONFIG["argument.integ"] and not os.path.exists(tor_config) and not stem.util.system.is_available(tor_config):
    print "Unable to start tor, '%s' does not exists." % tor_config
    sys.exit(1)

if __name__ == '__main__':
  try:
    stem.prereq.check_requriements()
  except ImportError, exc:
    print exc
    print
    
    sys.exit(1)
  
  start_time = time.time()
  
  # override flag to indicate at the end that testing failed somewhere
  testing_failed = False
  
  # loads and validates our various configurations
  test_config = stem.util.conf.get_config("test")
  
  settings_path = os.path.join(test.runner.STEM_BASE, "test", "settings.cfg")
  test_config.load(settings_path)
  
  load_user_configuration(test_config)
  
  if not CONFIG["argument.unit"] and not CONFIG["argument.integ"]:
    test.output.print_line("Nothing to run (for usage provide --help)\n")
    sys.exit()
  
  # if we have verbose logging then provide the testing config
  our_level = stem.util.log.logging_level(CONFIG["argument.log"])
  info_level = stem.util.log.logging_level(stem.util.log.INFO)
  
  if our_level <= info_level: test.output.print_config(test_config)
  
  error_tracker = test.output.ErrorTracker()
  output_filters = (
    error_tracker.get_filter(),
    test.output.strip_module,
    test.output.align_results,
    test.output.colorize,
  )
  
  stem_logger = log.get_logger()
  logging_buffer = log.LogBuffer(CONFIG["argument.log"])
  stem_logger.addHandler(logging_buffer)
  
  if CONFIG["argument.unit"]:
    test.output.print_divider("UNIT TESTS", True)
    error_tracker.set_category("UNIT TEST")
    
    for test_class in UNIT_TESTS:
      if CONFIG["argument.test"] and \
        not test_class.__module__.startswith(CONFIG["argument.test"]):
        continue
      
      test.output.print_divider(test_class.__module__)
      suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
      test_results = StringIO.StringIO()
      unittest.TextTestRunner(test_results, verbosity=2).run(suite)
      
      sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
      print
      
      test.output.print_logging(logging_buffer)
    
    print
  
  if CONFIG["argument.integ"]:
    test.output.print_divider("INTEGRATION TESTS", True)
    integ_runner = test.runner.get_runner()
    
    # Queue up all the targets with torrc options we want to run against.
    
    integ_run_targets = []
    all_run_targets = [t for t in Target if CONFIG["target.torrc"].get(t) != None]
    
    if test_config.get("integ.target.run.all", False):
      # test against everything with torrc options
      integ_run_targets = all_run_targets
    else:
      for target in all_run_targets:
        target_config = CONFIG["target.config"].get(target)
        
        if target_config and test_config.get(target_config, False):
          integ_run_targets.append(target)
    
    # if we didn't specify any targets then use the default
    if not integ_run_targets:
      integ_run_targets.append(DEFAULT_RUN_TARGET)
    
    # Determine targets we don't meet the prereqs for. Warnings are given about
    # these at the end of the test run so they're more noticeable.
    
    our_version, skip_targets = None, []
    
    for target in integ_run_targets:
      target_prereq = CONFIG["target.prereq"].get(target)
      
      if target_prereq:
        # lazy loaded to skip system call if we don't have any prereqs
        if not our_version:
          our_version = stem.version.get_system_tor_version(CONFIG["argument.tor"])
        
        if our_version < stem.version.Requirement[target_prereq]:
          skip_targets.append(target)
    
    for target in integ_run_targets:
      if target in skip_targets: continue
      error_tracker.set_category(target)
      
      try:
        # converts the 'target.torrc' csv into a list of test.runner.Torrc enums
        torrc_opts = []
        
        for opt in test_config.get_str_csv("target.torrc", [], sub_key = target):
          if opt in test.runner.Torrc.keys():
            torrc_opts.append(test.runner.Torrc[opt])
          else:
            test.output.print_line("'%s' isn't a test.runner.Torrc enumeration" % opt)
            sys.exit(1)
        
        integ_runner.start(CONFIG["argument.tor"], extra_torrc_opts = torrc_opts)
        
        test.output.print_line("Running tests...", term.Color.BLUE, term.Attr.BOLD)
        print
        
        for test_class in INTEG_TESTS:
          if CONFIG["argument.test"] and \
            not test_class.__module__.startswith(CONFIG["argument.test"]):
            continue
          
          test.output.print_divider(test_class.__module__)
          suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
          test_results = StringIO.StringIO()
          unittest.TextTestRunner(test_results, verbosity=2).run(suite)
          
          sys.stdout.write(test.output.apply_filters(test_results.getvalue(), *output_filters))
          print
          
          test.output.print_logging(logging_buffer)
        
        # We should have joined on all threads. If not then that indicates a
        # leak that could both likely be a bug and disrupt further targets.
        
        active_threads = threading.enumerate()
        
        if len(active_threads) > 1:
          test.output.print_line("Threads lingering after test run:", *ERROR_ATTR)
          
          for lingering_thread in active_threads:
            test.output.print_line("  %s" % lingering_thread, *ERROR_ATTR)
          
          testing_failed = True
          break
      except KeyboardInterrupt:
        test.output.print_line("  aborted starting tor: keyboard interrupt\n", *ERROR_ATTR)
        break
      except OSError:
        pass
      finally:
        integ_runner.stop()
    
    if skip_targets:
      print
      
      for target in skip_targets:
        req_version = stem.version.Requirement[CONFIG["target.prereq"][target]]
        test.output.print_line("Unable to run target %s, this requires tor version %s" % (target, req_version), term.Color.RED, term.Attr.BOLD)
      
      print
    
    # TODO: note unused config options afterward?
  
  whitespace_issues = test.check_whitespace.get_issues("stem")
  whitespace_issues.update(test.check_whitespace.get_issues("test"))
  whitespace_issues.update(test.check_whitespace.get_issues("run_tests.py"))
  
  if whitespace_issues:
    test.output.print_line("WHITESPACE ISSUES", term.Color.BLUE, term.Attr.BOLD)
    
    for file_path in whitespace_issues:
      test.output.print_line("* %s" % file_path, term.Color.BLUE, term.Attr.BOLD)
      
      for line_number, msg in whitespace_issues[file_path]:
        line_count = "%-4s" % line_number
        test.output.print_line("  line %s - %s" % (line_count, msg))
      
      print
  
  runtime = time.time() - start_time
  if runtime < 1: runtime_label = "(%0.1f seconds)" % runtime
  else: runtime_label = "(%i seconds)" % runtime
  
  if testing_failed or error_tracker.has_error_occured():
    test.output.print_line("TESTING FAILED %s" % runtime_label, *ERROR_ATTR)
    
    for line in error_tracker:
      test.output.print_line("  %s" % line, *ERROR_ATTR)
  else:
    test.output.print_line("TESTING PASSED %s" % runtime_label, term.Color.GREEN, term.Attr.BOLD)
    print

