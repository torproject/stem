"""
Runtime context for the integration tests. This is used both by the test runner
to start and stop tor, and by the integration tests themselves for information
about the tor test instance they're running against.

RunnerStopped - Runner doesn't have an active tor instance
TorInaccessable - Tor can't be queried for the information

exercise_socket - Does a basic sanity check that a control socket can be used

get_runner - Singleton for fetching our runtime context.
Runner - Runtime context for our integration tests.
  |- start - prepares and starts a tor instance for our tests to run against
  |- stop - stops our tor instance and cleans up any temporary files
  |- is_running - checks if our tor test instance is running
  |- is_accessible - checks if our tor instance can be connected to
  |- is_ptraceable - checks if DisableDebuggerAttachment is set
  |- get_options - custom torrc options used for our test instance
  |- get_test_dir - testing directory path
  |- get_torrc_path - path to our tor instance's torrc
  |- get_torrc_contents - contents of our tor instance's torrc
  |- get_pid - process id of our tor process
  |- get_tor_socket - provides a socket to the tor instance
  +- get_tor_version - provides the version of tor we're running against
"""

import os
import sys
import time
import stat
import shutil
import logging
import tempfile
import threading

import stem.socket
import stem.process
import stem.version
import stem.util.conf
import stem.util.enum
import stem.util.term as term
import test.output

CONFIG = {
  "integ.test_directory": "./test/data",
  "integ.log": "./test/data/log",
  "test.target.online": False,
  "test.target.relative_data_dir": False,
}

stem.util.conf.get_config("test").sync(CONFIG)

STATUS_ATTR = (term.Color.BLUE, term.Attr.BOLD)
SUBSTATUS_ATTR = (term.Color.BLUE, )
ERROR_ATTR = (term.Color.RED, term.Attr.BOLD)

BASE_TORRC = """# configuration for stem integration tests
DataDirectory %s
SocksPort 0
"""

# We make some paths relative to stem's base directory (the one above us)
# rather than the process' cwd. This doesn't end with a slash.
STEM_BASE = os.path.sep.join(__file__.split(os.path.sep)[:-2])

# singleton Runner instance
INTEG_RUNNER = None

# control authentication options and attributes
CONTROL_PASSWORD = "pw"
CONTROL_PORT = 1111
CONTROL_SOCKET_PATH = "/tmp/stem_integ/socket"

Torrc = stem.util.enum.Enum(
  ("PORT", "ControlPort %i" % CONTROL_PORT),
  ("COOKIE", "CookieAuthentication 1"),
  ("PASSWORD", "HashedControlPassword 16:8C423A41EF4A542C6078985270AE28A4E04D056FB63F9F201505DB8E06"),
  ("SOCKET", "ControlSocket %s" % CONTROL_SOCKET_PATH),
  ("PTRACE", "DisableDebuggerAttachment 0"),
)

class RunnerStopped(Exception):
  "Raised when we try to use a Runner that doesn't have an active tor instance"
  pass

class TorInaccessable(Exception):
  "Raised when information is needed from tor but the instance we have is inaccessable"
  pass

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

def get_runner():
  """
  Singleton for the runtime context of integration tests.
  """
  
  global INTEG_RUNNER
  if not INTEG_RUNNER: INTEG_RUNNER = Runner()
  return INTEG_RUNNER

class Runner:
  def __init__(self):
    self._runner_lock = threading.RLock()
    
    # runtime attributes, set by the start method
    self._test_dir = ""
    self._tor_cwd = ""
    self._torrc_contents = ""
    self._custom_opts = None
    self._tor_process = None
  
  def start(self, tor_cmd, extra_torrc_opts):
    """
    Makes temporary testing resources and starts tor, blocking until it
    completes.
    
    Arguments:
      tor_cmd (str) - command to start tor with
      extra_torrc_opts (list) - additional torrc options for our test instance
    
    Raises:
      OSError if unable to run test preparations or start tor
    """
    
    self._runner_lock.acquire()
    
    # if we're holding on to a tor process (running or not) then clean up after
    # it so we can start a fresh instance
    if self._tor_process: self.stop()
    
    test.output.print_line("Setting up a test instance...", *STATUS_ATTR)
    
    # if 'test_directory' is unset then we make a new data directory in /tmp
    # and clean it up when we're done
    
    config_test_dir = CONFIG["integ.test_directory"]
    
    if config_test_dir:
      self._test_dir = stem.util.system.expand_path(config_test_dir, STEM_BASE)
    else:
      self._test_dir = tempfile.mktemp("-stem-integ")
    
    original_cwd, data_dir_path = os.getcwd(), self._test_dir
    
    if CONFIG["test.target.relative_data_dir"]:
      tor_cwd = os.path.dirname(self._test_dir)
      if not os.path.exists(tor_cwd): os.makedirs(tor_cwd)
      
      os.chdir(tor_cwd)
      data_dir_path = "./%s" % os.path.basename(self._test_dir)
    
    self._custom_opts = extra_torrc_opts
    self._torrc_contents = BASE_TORRC % data_dir_path
    
    if extra_torrc_opts:
      self._torrc_contents += "\n".join(extra_torrc_opts) + "\n"
    
    try:
      self._tor_cwd = os.getcwd()
      self._run_setup()
      self._start_tor(tor_cmd)
      
      # revert our cwd back to normal
      if CONFIG["test.target.relative_data_dir"]:
        os.chdir(original_cwd)
    except OSError, exc:
      self.stop()
      raise exc
    finally:
      self._runner_lock.release()
  
  def stop(self):
    """
    Stops our tor test instance and cleans up any temporary resources.
    """
    
    self._runner_lock.acquire()
    test.output.print_noline("Shutting down tor... ", *STATUS_ATTR)
    
    if self._tor_process:
      self._tor_process.kill()
      self._tor_process.communicate() # blocks until the process is done
    
    # if we've made a temporary data directory then clean it up
    if self._test_dir and CONFIG["integ.test_directory"] == "":
      shutil.rmtree(self._test_dir, ignore_errors = True)
    
    self._test_dir = ""
    self._tor_cwd = ""
    self._torrc_contents = ""
    self._custom_opts = None
    self._tor_process = None
    
    test.output.print_line("done", *STATUS_ATTR)
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
  
  def is_accessible(self):
    """
    Checks if our tor instance has a method of being connected to or not.
    
    Returns:
      True if tor has a control socket or port, False otherwise
    """
    
    return Torrc.PORT in self._custom_opts or Torrc.SOCKET in self._custom_opts
  
  def is_ptraceable(self):
    """
    Checks if tor's 'DisableDebuggerAttachment' option is set. This feature has
    a lot of adverse side effects as per...
    https://trac.torproject.org/projects/tor/ticket/3313
    
    Returns:
      True if debugger attachment is disallowd, False otherwise
    
    Raises:
      TorInaccessable if this can't be determined
    """
    
    # TODO: replace higher level GETCONF query when we have a controller class
    control_socket = self.get_tor_socket()
    control_socket.send("GETCONF DisableDebuggerAttachment")
    getconf_response = control_socket.recv()
    control_socket.close()
    
    return str(getconf_response) != "DisableDebuggerAttachment=1"
  
  def get_options(self):
    """
    Provides the custom torrc options our tor instance is running with.
    
    Returns:
      list of Torrc enumerations being used by our test instance
    """
    
    return self._custom_opts
  
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
      stem.socket.ControlSocket connected with our testing instance
    
    Raises:
      TorInaccessable if tor can't be connected to
    """
    
    if Torrc.PORT in self._custom_opts:
      control_socket = stem.socket.ControlPort(control_port = CONTROL_PORT)
    elif Torrc.SOCKET in self._custom_opts:
      control_socket = stem.socket.ControlSocketFile(CONTROL_SOCKET_PATH)
    else: raise TorInaccessable("Unable to connect to tor")
    
    if authenticate:
      stem.connection.authenticate(control_socket, CONTROL_PASSWORD)
    
    return control_socket
  
  def get_tor_version(self):
    """
    Queries our test instance for tor's version.
    
    Returns:
      stem.version.Version for our test instance
    
    Raises:
      TorInaccessable if this can't be determined
    """
    
    # TODO: replace with higher level functions when we've completed a basic
    # controller class
    
    control_socket = self.get_tor_socket()
    
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
  
  def _run_setup(self):
    """
    Makes a temporary runtime resources of our integration test instance.
    
    Raises:
      OSError if unsuccessful
    """
    
    # makes a temporary data directory if needed
    try:
      test.output.print_noline("  making test directory (%s)... " % self._test_dir, *STATUS_ATTR)
      
      if os.path.exists(self._test_dir):
        test.output.print_line("skipped", *STATUS_ATTR)
      else:
        os.makedirs(self._test_dir)
        test.output.print_line("done", *STATUS_ATTR)
    except OSError, exc:
      test.output.print_line("failed (%s)" % exc, *ERROR_ATTR)
      raise exc
    
    # Makes a directory for the control socket if needed. As of, at least, Tor
    # 0.2.3.10 it checks during startup that the directory a control socket
    # resides in is only accessable by the tor user (and refuses to finish
    # starting if it isn't).
    
    if Torrc.SOCKET in self._custom_opts:
      try:
        socket_dir = os.path.dirname(CONTROL_SOCKET_PATH)
        test.output.print_noline("  making control socket directory (%s)... " % socket_dir, *STATUS_ATTR)
        
        if os.path.exists(socket_dir) and stat.S_IMODE(os.stat(socket_dir).st_mode) == 0700:
          test.output.print_line("skipped", *STATUS_ATTR)
        else:
          if not os.path.exists(socket_dir):
            os.makedirs(socket_dir)
          
          os.chmod(socket_dir, 0700)
          test.output.print_line("done", *STATUS_ATTR)
      except OSError, exc:
        test.output.print_line("failed (%s)" % exc, *ERROR_ATTR)
        raise exc
    
    # configures logging
    logging_path = CONFIG["integ.log"]
    
    if logging_path:
      logging_path = stem.util.system.expand_path(logging_path, STEM_BASE)
      test.output.print_noline("  configuring logger (%s)... " % logging_path, *STATUS_ATTR)
      
      # delete the old log
      if os.path.exists(logging_path):
        os.remove(logging_path)
      
      logging.basicConfig(
        filename = logging_path,
        level = logging.DEBUG,
        format = '%(asctime)s [%(levelname)s] %(message)s',
        datefmt = '%D %H:%M:%S',
      )
      
      test.output.print_line("done", *STATUS_ATTR)
    else:
      test.output.print_line("  configuring logger... skipped", *STATUS_ATTR)
    
    # writes our testing torrc
    torrc_dst = os.path.join(self._test_dir, "torrc")
    try:
      test.output.print_noline("  writing torrc (%s)... " % torrc_dst, *STATUS_ATTR)
      
      torrc_file = open(torrc_dst, "w")
      torrc_file.write(self._torrc_contents)
      torrc_file.close()
      
      test.output.print_line("done", *STATUS_ATTR)
      
      for line in self._torrc_contents.strip().splitlines():
        test.output.print_line("    %s" % line.strip(), *SUBSTATUS_ATTR)
      
      print
    except Exception, exc:
      test.output.print_line("failed (%s)\n" % exc, *ERROR_ATTR)
      raise OSError(exc)
  
  def _start_tor(self, tor_cmd):
    """
    Initializes a tor process. This blocks until initialization completes or we
    error out.
    
    Arguments:
      tor_cmd (str) - command to start tor with
    
    Raises:
      OSError if we either fail to create the tor process or reached a timeout
      without success
    """
    
    test.output.print_line("Starting tor...\n", *STATUS_ATTR)
    start_time = time.time()
    
    try:
      # wait to fully complete if we're running tests with network activity,
      # otherwise finish after local bootstraping
      complete_percent = 100 if CONFIG["test.target.online"] else 5
      
      # prints output from tor's stdout while it starts up
      print_init_line = lambda line: test.output.print_line("  %s" % line, *SUBSTATUS_ATTR)
      
      torrc_dst = os.path.join(self._test_dir, "torrc")
      self._tor_process = stem.process.launch_tor(tor_cmd, torrc_dst, complete_percent, print_init_line)
      
      runtime = time.time() - start_time
      test.output.print_line("  done (%i seconds)\n" % runtime, *STATUS_ATTR)
    except KeyboardInterrupt:
      test.output.print_line("  aborted starting tor: keyboard interrupt\n", *ERROR_ATTR)
      raise OSError("keyboard interrupt")
    except OSError, exc:
      test.output.print_line("  failed to start tor: %s\n" % exc, *ERROR_ATTR)
      raise exc

