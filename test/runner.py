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
  |- get_test_dir - testing directory path
  |- get_torrc_path - path to our tor instance's torrc
  |- get_torrc_contents - contents of our tor instance's torrc
  |- get_connection_type - method by which controllers can connect to tor
  |- get_pid - process id of our tor process
  |- get_tor_socket - provides a socket to the tor instance
  +- get_tor_version - provides the version of tor we're running against
"""

import os
import sys
import time
import socket
import shutil
import logging
import tempfile
import binascii
import threading

import stem.socket
import stem.process
import stem.version
import stem.util.conf
import stem.util.enum
import stem.util.term as term

DEFAULT_CONFIG = {
  "test.integ.test_directory": "./test/data",
  "test.integ.log": "./test/data/log",
  "test.integ.target.online": False,
  "test.integ.target.relative_data_dir": False,
}

# Methods for connecting to tor. General integration tests only run with the
# DEFAULT_TOR_CONNECTION, but expanded integ tests will run with all of them.

TorConnection = stem.util.enum.Enum("NONE", "OPEN", "PASSWORD", "COOKIE", "MULTIPLE", "SOCKET", "SCOOKIE")
DEFAULT_TOR_CONNECTION = TorConnection.OPEN

STATUS_ATTR = (term.Color.BLUE, term.Attr.BOLD)
SUBSTATUS_ATTR = (term.Color.BLUE, )
ERROR_ATTR = (term.Color.RED, term.Attr.BOLD)

BASE_TORRC = """# configuration for stem integration tests
DataDirectory %s
SocksPort 0
"""

# We make some paths relative to stem's base directory (the one above us)
# rather than the process' cwd. This doesn't end with a slash.
STEM_BASE = "/".join(__file__.split("/")[:-2])

# singleton Runner instance
INTEG_RUNNER = None

# control authentication options and attributes
CONTROL_PASSWORD = "pw"
CONTROL_PORT = 1111
CONTROL_SOCKET_PATH = "/tmp/stem_integ_socket"

OPT_PORT = "ControlPort %i" % CONTROL_PORT
OPT_COOKIE = "CookieAuthentication 1"
OPT_PASSWORD = "HashedControlPassword 16:8C423A41EF4A542C6078985270AE28A4E04D056FB63F9F201505DB8E06"
OPT_SOCKET = "ControlSocket %s" % CONTROL_SOCKET_PATH

# mapping of TorConnection to their options

CONNECTION_OPTS = {
  TorConnection.NONE: [],
  TorConnection.OPEN: [OPT_PORT],
  TorConnection.PASSWORD: [OPT_PORT, OPT_PASSWORD],
  TorConnection.COOKIE: [OPT_PORT, OPT_COOKIE],
  TorConnection.MULTIPLE: [OPT_PORT, OPT_PASSWORD, OPT_COOKIE],
  TorConnection.SOCKET: [OPT_SOCKET],
  TorConnection.SCOOKIE: [OPT_SOCKET, OPT_COOKIE],
}

def get_runner():
  """
  Singleton for the runtime context of integration tests.
  """
  
  global INTEG_RUNNER
  if not INTEG_RUNNER: INTEG_RUNNER = Runner()
  return INTEG_RUNNER

def get_torrc(connection_type = DEFAULT_TOR_CONNECTION):
  """
  Provides a basic torrc with the given connection method. Hashed passwords are
  for "pw".
  """
  
  connection_opt, torrc = CONNECTION_OPTS[connection_type], BASE_TORRC
  
  if connection_opt:
    return torrc + "\n".join(connection_opt) + "\n"
  else: return torrc

def exercise_socket(test_case, control_socket):
  """
  Checks that we can now use the socket by issuing a 'GETINFO config-file'
  query.
  
  Arguments:
    test_case (unittest.TestCase) - unit testing case being ran
    control_socket (stem.socket.ControlSocket) - socket to be tested
  """
  
  torrc_path = get_runner().get_torrc_path()
  control_socket.send("GETINFO config-file")
  config_file_response = control_socket.recv()
  test_case.assertEquals("config-file=%s\nOK" % torrc_path, str(config_file_response))

class RunnerStopped(Exception):
  "Raised when we try to use a Runner that doesn't have an active tor instance"
  pass

class Runner:
  def __init__(self):
    self._config = dict(DEFAULT_CONFIG)
    self._runner_lock = threading.RLock()
    
    # runtime attributes, set by the start method
    self._test_dir = ""
    self._tor_cwd = ""
    self._torrc_contents = ""
    self._connection_type = None
    self._tor_process = None
  
  def start(self, connection_type = DEFAULT_TOR_CONNECTION, quiet = False):
    """
    Makes temporary testing resources and starts tor, blocking until it
    completes.
    
    Arguments:
      connection_type (TorConnection) - method for controllers to authenticate
                          to tor
      quiet (bool) - if False then this prints status information as we start
                     up to stdout
    
    Raises:
      OSError if unable to run test preparations or start tor
    """
    
    self._runner_lock.acquire()
    
    test_config = stem.util.conf.get_config("test")
    test_config.update(self._config)
    
    # if we're holding on to a tor process (running or not) then clean up after
    # it so we can start a fresh instance
    if self._tor_process: self.stop(quiet)
    
    _print_status("Setting up a test instance...\n", STATUS_ATTR, quiet)
    
    # if 'test_directory' is unset then we make a new data directory in /tmp
    # and clean it up when we're done
    
    config_test_dir = self._config["test.integ.test_directory"]
    
    if config_test_dir:
      self._test_dir = stem.util.system.expand_path(config_test_dir, STEM_BASE)
    else:
      self._test_dir = tempfile.mktemp("-stem-integ")
    
    original_cwd, data_dir_path = os.getcwd(), self._test_dir
    
    if self._config["test.integ.target.relative_data_dir"]:
      tor_cwd = os.path.dirname(self._test_dir)
      if not os.path.exists(tor_cwd): os.makedirs(tor_cwd)
      
      os.chdir(tor_cwd)
      data_dir_path = "./%s" % os.path.basename(self._test_dir)
    
    self._connection_type = connection_type
    self._torrc_contents = get_torrc(connection_type) % data_dir_path
    
    try:
      self._tor_cwd = os.getcwd()
      self._run_setup(quiet)
      self._start_tor(quiet)
      
      # revert our cwd back to normal
      if self._config["test.integ.target.relative_data_dir"]:
        os.chdir(original_cwd)
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
    self._tor_cwd = ""
    self._torrc_contents = ""
    self._connection_type = None
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
  
  def get_test_dir(self):
    """
    Provides the absolute path for our testing directory.
    
    Returns:
      str with our test direcectory path
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    return self._get("_test_dir")
  
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
  
  def get_auth_cookie_path(self):
    """
    Provides the absolute path for our authentication cookie if we have one.
    
    Returns:
      str with our auth cookie path
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    test_dir = self._get("_test_dir")
    return os.path.join(test_dir, "control_auth_cookie")
  
  def get_tor_cwd(self):
    """
    Provides the current working directory of our tor process.
    """
    
    return self._get("_tor_cwd")
  
  def get_torrc_contents(self):
    """
    Provides the contents of our torrc.
    
    Returns:
      str with the contents of our torrc, lines are newline separated
    
    Raises:
      RunnerStopped if we aren't running
    """
    
    return self._get("_torrc_contents")
  
  def get_connection_type(self):
    """
    Provides the method we can use for connecting to the tor instance.
    
    Returns:
      test.runner.TorConnection enumeration for the method we can use for
      connecting to the tor test instance
    """
    
    return self._connection_type
  
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
  
  def get_tor_socket(self, authenticate = True):
    """
    Provides a socket connected to the tor test instance's control socket.
    
    Arguments:
      authenticate (bool) - if True then the socket is authenticated
    
    Returns:
      stem.socket.ControlSocket connected with our testing instance, returning
      None if we either don't have a test instance or it can't be connected to
    """
    
    connection_type, cookie_path = self.get_connection_type(), self.get_auth_cookie_path()
    if connection_type == None: return None
    
    conn_opts = CONNECTION_OPTS[connection_type]
    
    if OPT_PORT in conn_opts:
      control_socket = stem.socket.ControlPort(control_port = CONTROL_PORT)
    elif OPT_SOCKET in conn_opts:
      control_socket = stem.socket.ControlSocketFile(CONTROL_SOCKET_PATH)
    else: return None
    
    if authenticate:
      stem.connection.authenticate(control_socket, CONTROL_PASSWORD)
    
    return control_socket
  
  def get_tor_version(self):
    """
    Queries our test instance for tor's version.
    
    Returns:
      stem.version.Version for our test instance, None if we're unable to
      connect to it
    """
    
    # TODO: replace with higher level functions when we've completed a basic
    # controller class
    
    control_socket = self.get_tor_socket()
    if not control_socket: return None
    
    control_socket.send("GETINFO version")
    version_response = control_socket.recv()
    control_socket.close()
    
    tor_version = list(version_response)[0][8:]
    return stem.version.Version(tor_version)
  
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
    
    # configures logging
    logging_path = self._config["test.integ.log"]
    
    if logging_path:
      logging_path = stem.util.system.expand_path(logging_path, STEM_BASE)
      _print_status("  configuring logger (%s)... " % logging_path, STATUS_ATTR, quiet)
      
      # delete the old log
      if os.path.exists(logging_path):
        os.remove(logging_path)
      
      logging.basicConfig(
        filename = logging_path,
        level = logging.DEBUG,
        format = '%(asctime)s [%(levelname)s] %(message)s',
        datefmt = '%D %H:%M:%S',
      )
      
      _print_status("done\n", STATUS_ATTR, quiet)
    else:
      _print_status("  configuring logger... skipped\n", STATUS_ATTR, quiet)
    
    # writes our testing torrc
    torrc_dst = os.path.join(self._test_dir, "torrc")
    try:
      _print_status("  writing torrc (%s)... " % torrc_dst, STATUS_ATTR, quiet)
      
      torrc_file = open(torrc_dst, "w")
      torrc_file.write(self._torrc_contents)
      torrc_file.close()
      
      _print_status("done\n", STATUS_ATTR, quiet)
      
      for line in self._torrc_contents.strip().splitlines():
        _print_status("    %s\n" % line.strip(), SUBSTATUS_ATTR, quiet)
      
      _print_status("\n", (), quiet)
    except Exception, exc:
      _print_status("failed (%s)\n\n" % exc, ERROR_ATTR, quiet)
      raise OSError(exc)
  
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
      complete_percent = 100 if self._config["test.integ.target.online"] else 5
      
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

