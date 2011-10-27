"""
Runtime context for the integration tests. This is used both by the test runner
to start and stop tor, and by the integration tests themselves for information
about the tor test instance they're running against.

RunnerStopped - Runner doesn't have an active tor instance.

get_runner - Singleton for fetching our runtime context.
Runner - Runtime context for our integration tests.
  |- start - prepares and starts a tor instance for our tests to run against
  |- stop - stops our tor instance and cleans up any temporary files
  |- is_running - checks if our tor test instance is running
  |- get_torrc_path - path to our tor instance's torrc
  |- get_torrc_contents - contents of our tor instance's torrc
  |- get_control_port - port that our tor instance is listening on
  +- get_pid - process id of our tor process
"""

import os
import sys
import time
import shutil
import tempfile
import threading

import stem.process

from stem.util import term

DEFAULT_CONFIG = {
  "test.integ.test_directory": "./test/data",
  "test.integ.run.online": False,
}

STATUS_ATTR = (term.Color.BLUE, term.Attr.BOLD)
SUBSTATUS_ATTR = (term.Color.BLUE, )
ERROR_ATTR = (term.Color.RED, term.Attr.BOLD)

BASIC_TORRC = """# configuration for stem integration tests
DataDirectory %s
SocksPort 0
ControlPort 1111
"""

# singleton Runner instance
INTEG_RUNNER = None

def get_runner():
  """
  Singleton for the runtime context of integration tests.
  """
  
  global INTEG_RUNNER
  if not INTEG_RUNNER: INTEG_RUNNER = Runner()
  return INTEG_RUNNER

class RunnerStopped(Exception):
  "Raised when we try to use a Runner that doesn't have an active tor instance"
  pass

class Runner:
  def __init__(self):
    self._config = dict(DEFAULT_CONFIG)
    self._runner_lock = threading.RLock()
    
    # runtime attributes, set by the start method
    self._test_dir = ""
    self._torrc_contents = ""
    self._tor_process = None
  
  def start(self, quiet = False, user_config = None):
    """
    Makes temporary testing resources and starts tor, blocking until it
    completes.
    
    Arguments:
      quiet (bool) - if False then this prints status information as we start
                     up to stdout
      user_config (stem.util.conf.Config) - custom test configuration
    
    Raises:
      OSError if unable to run test preparations or start tor
    """
    
    self._runner_lock.acquire()
    
    # if we're holding on to a tor process (running or not) then clean up after
    # it so we can start a fresh instance
    if self._tor_process: self.stop(quiet)
    
    # apply any custom configuration attributes
    if user_config: user_config.update(self._config)
    
    # if 'test_directory' is unset then we make a new data directory in /tmp
    # and clean it up when we're done
    
    config_test_dir = self._config["test.integ.test_directory"]
    
    if config_test_dir:
      # makes paths relative of stem's base directory (the one above us)
      if config_test_dir.startswith("./"):
        stem_base = "/".join(__file__.split("/")[:-2])
        config_test_dir = stem_base + config_test_dir[1:]
      
      self._test_dir = os.path.expanduser(config_test_dir)
    else:
      self._test_dir = tempfile.mktemp("-stem-integ")
    
    self._torrc_contents = BASIC_TORRC % self._test_dir
    
    try:
      self._run_setup(quiet)
      self._start_tor(quiet)
    except OSError, exc:
      self.stop(quiet)
      raise exc
    finally:
      self._runner_lock.release()
  
  def stop(self, quiet = False):
    """
    Stops our tor test instance and cleans up any temporary resources.
    
    Argument:
      quiet (bool) - prints status information to stdout if False
    """
    
    self._runner_lock.acquire()
    _print_status("Shutting down tor... ", STATUS_ATTR, quiet)
    
    if self._tor_process:
      self._tor_process.kill()
      self._tor_process.communicate() # blocks until the process is done
    
    # if we've made a temporary data directory then clean it up
    if self._test_dir and self._config["test.integ.test_directory"] == "":
      shutil.rmtree(self._test_dir, ignore_errors = True)
    
    self._test_dir = ""
    self._torrc_contents = ""
    self._tor_process = None
    
    _print_status("done\n", STATUS_ATTR, quiet)
    self._runner_lock.release()
  
  def is_running(self):
    """
    Checks if we're running a tor test instance and that it's alive.
    
    Returns:
      True if we have a running tor test instance, False otherwise
    """
    
    # subprocess.Popen.poll() checks the return code, returning None if it's
    # still going
    
    self._runner_lock.acquire()
    is_running = self._tor_process and self._tor_process.poll() == None
    
    # If the tor process closed unexpectedly then this is probably the first
    # place that we're realizing it. Clean up the temporary resources now since
    # we might not end up calling stop() as normal.
    
    if not is_running: self.stop(True)
    
    self._runner_lock.release()
    
    return is_running
  
  def get_torrc_path(self):
    """
    Provides the absolute path for where our testing torrc resides.
    
    Returns:
      str with our torrc path
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    test_dir = self._get("_test_dir")
    return os.path.join(test_dir, "torrc")
  
  def get_torrc_contents(self):
    """
    Provides the contents of our torrc.
    
    Returns:
      str with the contents of our torrc, lines are newline separated
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    return self._get("_torrc_contents")
  
  def get_control_port(self):
    """
    Provides the control port tor is running with.
    
    Returns:
      int for the port tor's controller interface is bound to, None if it
      doesn't have one
    
    Raises:
      RunnerStopped if we aren't running
      ValueError if our torrc has a malformed ControlPort entry
    """
    
    torrc_contents = self.get_torrc_contents()
    
    for line in torrc_contents.split("\n"):
      line_comp = line.strip().split()
      
      if line_comp[0] == "ControlPort":
        if len(line_comp) == 2 and line_comp[1].isdigit():
          return int(line_comp[1])
        else:
          raise ValueError("Malformed ControlPort entry: %s" % line)
    
    # torrc doesn't have a ControlPort
    return None
  
  def get_pid(self):
    """
    Provides the process id of the tor process.
    
    Returns:
      int pid for the tor process
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    tor_process = self._get("_tor_process")
    return tor_process.pid
  
  def _get(self, attr):
    """
    Fetches one of our attributes in a thread safe manner, raising if we aren't
    running.
    
    Arguments:
      attr (str) - class variable that we want to fetch
    
    Returns:
      value of the fetched variable
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    try:
      self._runner_lock.acquire()
      
      if self.is_running():
        return self.__dict__[attr]
      else: raise RunnerStopped()
    finally:
      self._runner_lock.release()
  
  def _run_setup(self, quiet):
    """
    Makes a temporary runtime resources of our integration test instance.
    
    Arguments:
      quiet (bool) - prints status information to stdout if False
    
    Raises:
      OSError if unsuccessful
    """
    
    _print_status("Setting up a test instance...\n", STATUS_ATTR, quiet)
    
    # makes a temporary data directory if needed
    try:
      _print_status("  making test directory (%s)... " % self._test_dir, STATUS_ATTR, quiet)
      
      if os.path.exists(self._test_dir):
        _print_status("skipped\n", STATUS_ATTR, quiet)
      else:
        os.makedirs(self._test_dir)
        _print_status("done\n", STATUS_ATTR, quiet)
    except OSError, exc:
      _print_status("failed (%s)\n" % exc, ERROR_ATTR, quiet)
      raise exc
    
    # writes our testing torrc
    torrc_dst = os.path.join(self._test_dir, "torrc")
    try:
      _print_status("  writing torrc (%s)... " % torrc_dst, STATUS_ATTR, quiet)
      
      torrc_file = open(torrc_dst, "w")
      torrc_file.write(self._torrc_contents)
      torrc_file.close()
      
      _print_status("done\n", STATUS_ATTR, quiet)
      
      for line in self._torrc_contents.strip().split("\n"):
        _print_status("    %s\n" % line.strip(), SUBSTATUS_ATTR, quiet)
      
      _print_status("\n", (), quiet)
    except Exception, exc:
      _print_status("failed (%s)\n\n" % exc, ERROR_ATTR, quiet)
      raise exc
  
  def _start_tor(self, quiet):
    """
    Initializes a tor process. This blocks until initialization completes or we
    error out.
    
    Arguments:
      quiet (bool) - prints status information to stdout if False
    
    Raises:
      OSError if we either fail to create the tor process or reached a timeout
      without success
    """
    
    _print_status("Starting tor...\n", STATUS_ATTR, quiet)
    start_time = time.time()
    
    try:
      # wait to fully complete if we're running tests with network activity,
      # otherwise finish after local bootstraping
      complete_percent = 100 if self._config["test.integ.run.online"] else 5
      
      # prints output from tor's stdout while it starts up
      print_init_line = lambda line: _print_status("  %s\n" % line, SUBSTATUS_ATTR, quiet)
      
      torrc_dst = os.path.join(self._test_dir, "torrc")
      self._tor_process = stem.process.launch_tor(torrc_dst, complete_percent, print_init_line)
      
      runtime = time.time() - start_time
      _print_status("  done (%i seconds)\n\n" % runtime, STATUS_ATTR, quiet)
    except KeyboardInterrupt:
      _print_status("  aborted starting tor: keyboard interrupt\n\n", ERROR_ATTR, quiet)
      raise OSError("keyboard interrupt")
    except OSError, exc:
      _print_status("  failed to start tor: %s\n\n" % exc, ERROR_ATTR, quiet)
      raise exc

def _print_status(msg, attr = (), quiet = False):
  """
  Short alias for printing status messages.
  
  Arguments:
    msg (str)    - text to be printed
    attr (tuple) - list of term attributes to be applied to the text
    quiet (bool) - no-op if true, prints otherwise
  """
  
  if not quiet:
    sys.stdout.write(term.format(msg, *attr))

