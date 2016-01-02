# Copyright 2011-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Runtime context for the integration tests. This is used both by the test runner
to start and stop tor, and by the integration tests themselves for information
about the tor test instance they're running against.

::

  RunnerStopped - Runner doesn't have an active tor instance
  TorInaccessable - Tor can't be queried for the information

  skip - skips the current test if we can
  require_controller - skips the test unless tor provides a controller endpoint
  require_version - skips the test unless we meet a tor version requirement
  require_online - skips unless targets allow for online tests
  only_run_once - skip the test if it has been ran before
  exercise_controller - basic sanity check that a controller connection can be used

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
    |- get_auth_cookie_path - path for our authentication cookie if we have one
    |- get_tor_cwd - current working directory of our tor process
    |- get_chroot - provides the path of our emulated chroot if we have one
    |- get_pid - process id of our tor process
    |- get_tor_socket - provides a socket to our test instance
    |- get_tor_controller - provides a controller for our test instance
    |- get_tor_version - provides the version of tor we're running against
    +- get_tor_command - provides the command used to start tor
"""

import logging
import os
import shutil
import stat
import tempfile
import threading
import time
import uuid

import stem.connection
import stem.prereq
import stem.process
import stem.socket
import stem.util.conf
import stem.util.enum
import stem.version

from test.output import println, STATUS, ERROR, SUBSTATUS, NO_NL
from test.util import Target, STEM_BASE

CONFIG = stem.util.conf.config_dict('test', {
  'integ.test_directory': './test/data',
  'integ.log': './test/data/log',
})

SOCKS_HOST = '127.0.0.1'
SOCKS_PORT = 1112

BASE_TORRC = """# configuration for stem integration tests
DataDirectory %%s
SocksListenAddress %s:%i
DownloadExtraInfo 1
Log notice stdout
Log notice file %%s/tor_log
""" % (SOCKS_HOST, SOCKS_PORT)

# singleton Runner instance
INTEG_RUNNER = None

# control authentication options and attributes
CONTROL_PASSWORD = 'pw'
CONTROL_PORT = 1111
CONTROL_SOCKET_PATH = os.path.join(tempfile.gettempdir(), str(uuid.uuid4()), 'socket')

Torrc = stem.util.enum.Enum(
  ('PORT', 'ControlPort %i' % CONTROL_PORT),
  ('COOKIE', 'CookieAuthentication 1'),
  ('PASSWORD', 'HashedControlPassword 16:8C423A41EF4A542C6078985270AE28A4E04D056FB63F9F201505DB8E06'),
  ('SOCKET', 'ControlSocket %s' % CONTROL_SOCKET_PATH),
  ('PTRACE', 'DisableDebuggerAttachment 0'),
)

# (test_instance, test_name) tuples that we've registered as having been ran
RAN_TESTS = []


class RunnerStopped(Exception):
  "Raised when we try to use a Runner that doesn't have an active tor instance"


class TorInaccessable(Exception):
  'Raised when information is needed from tor but the instance we have is inaccessible'


def skip(test_case, message):
  """
  Skips the test if we can. The capability for skipping tests was added in
  python 2.7 so callers should return after this, so they report 'success' if
  this method is unavailable.

  :param unittest.TestCase test_case: test being ran
  :param str message: message to skip the test with
  """

  if not stem.prereq._is_python_26():
    test_case.skipTest(message)


def require_controller(func):
  """
  Skips the test unless tor provides an endpoint for controllers to attach to.
  """

  def wrapped(self, *args, **kwargs):
    if get_runner().is_accessible():
      return func(self, *args, **kwargs)
    else:
      skip(self, '(no connection)')

  return wrapped


def require_version(req_version):
  """
  Skips the test unless we meet the required version.

  :param stem.version.Version req_version: required tor version for the test
  """

  def decorator(func):
    def wrapped(self, *args, **kwargs):
      if get_runner().get_tor_version() >= req_version:
        return func(self, *args, **kwargs)
      else:
        skip(self, '(requires %s)' % req_version)

    return wrapped

  return decorator


def require_online(func):
  """
  Skips the test if we weren't started with the ONLINE target, which indicates
  that tests requiring network connectivity should run.
  """

  def wrapped(self, *args, **kwargs):
    if Target.ONLINE in get_runner().attribute_targets:
      return func(self, *args, **kwargs)
    else:
      skip(self, '(requires online target)')

  return wrapped


def only_run_once(func):
  """
  Skips the test if it has ran before. If it hasn't then flags it as being ran.
  This is useful to prevent lengthy tests that are independent of integ targets
  from being run repeatedly with ``RUN_ALL``.
  """

  def wrapped(self, *args, **kwargs):
    if (self, self.id()) not in RAN_TESTS:
      RAN_TESTS.append((self, self.id()))
      return func(self, *args, **kwargs)
    else:
      skip(self, '(already ran)')

  return wrapped


def exercise_controller(test_case, controller):
  """
  Checks that we can now use the socket by issuing a 'GETINFO config-file'
  query. Controller can be either a :class:`stem.socket.ControlSocket` or
  :class:`stem.control.BaseController`.

  :param unittest.TestCase test_case: test being ran
  :param controller: tor controller connection to be authenticated
  """

  runner = get_runner()
  torrc_path = runner.get_torrc_path()

  if isinstance(controller, stem.socket.ControlSocket):
    controller.send('GETINFO config-file')
    config_file_response = controller.recv()
  else:
    config_file_response = controller.msg('GETINFO config-file')

  test_case.assertEqual('config-file=%s\nOK' % torrc_path, str(config_file_response))


def get_runner():
  """
  Singleton for the runtime context of integration tests.

  :returns: :class:`test.runner.Runner` with context for our integration tests
  """

  global INTEG_RUNNER

  if not INTEG_RUNNER:
    INTEG_RUNNER = Runner()

  return INTEG_RUNNER


class _MockChrootFile(object):
  """
  Wrapper around a file object that strips given content from readline()
  responses. This is used to simulate a chroot setup by removing the prefix
  directory from the paths we report.
  """

  def __init__(self, wrapped_file, strip_text):
    self.wrapped_file = wrapped_file
    self.strip_text = strip_text

  def readline(self):
    return self.wrapped_file.readline().replace(self.strip_text, '')


class Runner(object):
  def __init__(self):
    self.run_target = None
    self.attribute_targets = []

    self._runner_lock = threading.RLock()

    # runtime attributes, set by the start method

    self._test_dir = ''
    self._tor_cmd = None
    self._tor_cwd = ''
    self._torrc_contents = ''
    self._custom_opts = None
    self._tor_process = None
    self._chroot_path = None

    # set if we monkey patch stem.socket.recv_message()

    self._original_recv_message = None

  def start(self, run_target, attribute_targets, tor_cmd, extra_torrc_opts):
    """
    Makes temporary testing resources and starts tor, blocking until it
    completes.

    :param Target run_target: configuration we're running with
    :param list attribute_targets: **Targets** for our non-configuration attributes
    :param str tor_cmd: command to start tor with
    :param list extra_torrc_opts: additional torrc options for our test instance

    :raises: OSError if unable to run test preparations or start tor
    """

    with self._runner_lock:
      self.run_target = run_target
      self.attribute_targets = attribute_targets

      # if we're holding on to a tor process (running or not) then clean up after
      # it so we can start a fresh instance

      if self._tor_process:
        self.stop()

      println('Setting up a test instance...', STATUS)

      # if 'test_directory' is unset then we make a new data directory in /tmp
      # and clean it up when we're done

      config_test_dir = CONFIG['integ.test_directory']

      if config_test_dir:
        self._test_dir = stem.util.system.expand_path(config_test_dir, STEM_BASE)
      else:
        self._test_dir = tempfile.mktemp('-stem-integ')

      original_cwd, data_dir_path = os.getcwd(), self._test_dir

      if Target.RELATIVE in self.attribute_targets:
        tor_cwd = os.path.dirname(self._test_dir)

        if not os.path.exists(tor_cwd):
          os.makedirs(tor_cwd)

        os.chdir(tor_cwd)
        data_dir_path = './%s' % os.path.basename(self._test_dir)

      self._tor_cmd = tor_cmd
      self._custom_opts = extra_torrc_opts
      self._torrc_contents = BASE_TORRC % (data_dir_path, data_dir_path)

      if extra_torrc_opts:
        self._torrc_contents += '\n'.join(extra_torrc_opts) + '\n'

      try:
        self._tor_cwd = os.getcwd()
        self._run_setup()
        self._start_tor(tor_cmd)

        # strip the testing directory from recv_message responses if we're
        # simulating a chroot setup

        if Target.CHROOT in self.attribute_targets and not self._original_recv_message:
          # TODO: when we have a function for telling stem the chroot we'll
          # need to set that too

          self._original_recv_message = stem.socket.recv_message
          self._chroot_path = data_dir_path

          def _chroot_recv_message(control_file):
            return self._original_recv_message(_MockChrootFile(control_file, data_dir_path))

          stem.socket.recv_message = _chroot_recv_message

        # revert our cwd back to normal
        if Target.RELATIVE in self.attribute_targets:
          os.chdir(original_cwd)
      except OSError as exc:
        raise exc

  def stop(self):
    """
    Stops our tor test instance and cleans up any temporary resources.
    """

    with self._runner_lock:
      println('Shutting down tor... ', STATUS, NO_NL)

      if self._tor_process:
        # if the tor process has stopped on its own then the following raises
        # an OSError ([Errno 3] No such process)

        try:
          self._tor_process.kill()
        except OSError:
          pass

        self._tor_process.wait()  # blocks until the process is done

      # if we've made a temporary data directory then clean it up
      if self._test_dir and CONFIG['integ.test_directory'] == '':
        shutil.rmtree(self._test_dir, ignore_errors = True)

      # reverts any mocking of stem.socket.recv_message
      if self._original_recv_message:
        stem.socket.recv_message = self._original_recv_message
        self._original_recv_message = None

      # clean up our socket directory if we made one
      socket_dir = os.path.dirname(CONTROL_SOCKET_PATH)

      if os.path.exists(socket_dir):
        shutil.rmtree(socket_dir, ignore_errors = True)

      self._test_dir = ''
      self._tor_cmd = None
      self._tor_cwd = ''
      self._torrc_contents = ''
      self._custom_opts = None
      self._tor_process = None

      println('done', STATUS)

  def is_running(self):
    """
    Checks if we're running a tor test instance and that it's alive.

    :returns: True if we have a running tor test instance, False otherwise
    """

    with self._runner_lock:
      # Check for an unexpected shutdown by calling subprocess.Popen.poll(),
      # which returns the exit code or None if we're still running.

      if self._tor_process and self._tor_process.poll() is not None:
        # clean up the temporary resources and note the unexpected shutdown
        self.stop()
        println('tor shut down unexpectedly', ERROR)

      return bool(self._tor_process)

  def is_accessible(self):
    """
    Checks if our tor instance has a method of being connected to or not.

    :returns: True if tor has a control socket or port, False otherwise
    """

    return Torrc.PORT in self._custom_opts or Torrc.SOCKET in self._custom_opts

  def is_ptraceable(self):
    """
    Checks if tor's 'DisableDebuggerAttachment' option is set. This feature has
    a lot of adverse side effects (:trac:`3313`).

    :returns: True if debugger attachment is allowed, False otherwise
    """

    # If we're running a tor version where ptrace is disabled and we didn't
    # set 'DisableDebuggerAttachment=1' then we can infer that it's disabled.

    tor_version = self.get_tor_version()
    has_option = tor_version >= stem.version.Requirement.TORRC_DISABLE_DEBUGGER_ATTACHMENT
    return not has_option or Torrc.PTRACE in self.get_options()

  def get_options(self):
    """
    Provides the custom torrc options our tor instance is running with.

    :returns: list of Torrc enumerations being used by our test instance
    """

    return self._custom_opts

  def get_test_dir(self, resource = None):
    """
    Provides the absolute path for our testing directory or a file within it.

    :param str resource: file within our test directory to provide the path for

    :returns: str with our test directory's absolute path or that of a file within it

    :raises: :class:`test.runner.RunnerStopped` if we aren't running
    """

    if resource:
      return os.path.join(self._get('_test_dir'), resource)
    else:
      return self._get('_test_dir')

  def get_torrc_path(self, ignore_chroot = False):
    """
    Provides the absolute path for where our testing torrc resides.

    :param bool ignore_chroot: provides the real path, rather than the one that tor expects if True

    :returns: str with our torrc path

    :raises: RunnerStopped if we aren't running
    """

    test_dir = self._get('_test_dir')
    torrc_path = os.path.join(test_dir, 'torrc')

    if not ignore_chroot and self._chroot_path and torrc_path.startswith(self._chroot_path):
      torrc_path = torrc_path[len(self._chroot_path):]

    return torrc_path

  def get_torrc_contents(self):
    """
    Provides the contents of our torrc.

    :returns: str with the contents of our torrc, lines are newline separated

    :raises: :class:`test.runner.RunnerStopped` if we aren't running
    """

    return self._get('_torrc_contents')

  def get_auth_cookie_path(self):
    """
    Provides the absolute path for our authentication cookie if we have one.
    If running with an emulated chroot this is uneffected, still providing the
    real path.

    :returns: str with our auth cookie path

    :raises: :class:`test.runner.RunnerStopped` if we aren't running
    """

    test_dir = self._get('_test_dir')
    return os.path.join(test_dir, 'control_auth_cookie')

  def get_tor_cwd(self):
    """
    Provides the current working directory of our tor process.
    """

    return self._get('_tor_cwd')

  def get_chroot(self):
    """
    Provides the path we're using to emulate a chroot environment. This is None
    if we aren't emulating a chroot setup.

    :returns: str with the path of our emulated chroot
    """

    return self._chroot_path

  def get_pid(self):
    """
    Provides the process id of the tor process.

    :returns: int pid for the tor process

    :raises: :class:`test.runner.RunnerStopped` if we aren't running
    """

    tor_process = self._get('_tor_process')
    return tor_process.pid

  def get_tor_socket(self, authenticate = True):
    """
    Provides a socket connected to our tor test instance.

    :param bool authenticate: if True then the socket is authenticated

    :returns: :class:`stem.socket.ControlSocket` connected with our testing instance

    :raises: :class:`test.runner.TorInaccessable` if tor can't be connected to
    """

    if Torrc.PORT in self._custom_opts:
      control_socket = stem.socket.ControlPort(port = CONTROL_PORT)
    elif Torrc.SOCKET in self._custom_opts:
      control_socket = stem.socket.ControlSocketFile(CONTROL_SOCKET_PATH)
    else:
      raise TorInaccessable('Unable to connect to tor')

    if authenticate:
      stem.connection.authenticate(control_socket, CONTROL_PASSWORD, self.get_chroot())

    return control_socket

  def get_tor_controller(self, authenticate = True):
    """
    Provides a controller connected to our tor test instance.

    :param bool authenticate: if True then the socket is authenticated

    :returns: :class:`stem.socket.Controller` connected with our testing instance

    :raises: :class: `test.runner.TorInaccessable` if tor can't be connected to
    """

    control_socket = self.get_tor_socket(False)
    controller = stem.control.Controller(control_socket)

    if authenticate:
      controller.authenticate(password = CONTROL_PASSWORD, chroot_path = self.get_chroot())

    return controller

  def get_tor_version(self):
    """
    Queries our test instance for tor's version.

    :returns: :class:`stem.version.Version` for our test instance
    """

    try:
      # TODO: replace with higher level functions when we've completed a basic
      # controller class

      control_socket = self.get_tor_socket()

      control_socket.send('GETINFO version')
      version_response = control_socket.recv()
      control_socket.close()

      tor_version = list(version_response)[0]
      tor_version = tor_version[8:]

      if ' ' in tor_version:
        tor_version = tor_version.split(' ', 1)[0]

      return stem.version.Version(tor_version)
    except TorInaccessable:
      return stem.version.get_system_tor_version(self.get_tor_command())

  def get_tor_command(self, base_cmd = False):
    """
    Provides the command used to run our tor instance.

    :param bool base_cmd: provides just the command name if true rather than
      the full '--tor path' argument
    """

    return os.path.basename(self._get('_tor_cmd')) if base_cmd else self._get('_tor_cmd')

  def _get(self, attr):
    """
    Fetches one of our attributes in a thread safe manner, raising if we aren't
    running.

    :param str attr: class variable that we want to fetch

    :returns: value of the fetched variable

    :returns: :class:`test.runner.RunnerStopped` if we aren't running
    """

    with self._runner_lock:
      if self.is_running():
        return self.__dict__[attr]
      else:
        raise RunnerStopped()

  def _run_setup(self):
    """
    Makes a temporary runtime resources of our integration test instance.

    :raises: OSError if unsuccessful
    """

    # makes a temporary data directory if needed
    try:
      println('  making test directory (%s)... ' % self._test_dir, STATUS, NO_NL)

      if os.path.exists(self._test_dir):
        println('skipped', STATUS)
      else:
        os.makedirs(self._test_dir)
        println('done', STATUS)
    except OSError as exc:
      println('failed (%s)' % exc, ERROR)
      raise exc

    # Tor checks during startup that the directory a control socket resides in
    # is only accessible by the tor user (and refuses to finish starting if it
    # isn't).

    if Torrc.SOCKET in self._custom_opts:
      try:
        socket_dir = os.path.dirname(CONTROL_SOCKET_PATH)
        println('  making control socket directory (%s)... ' % socket_dir, STATUS, NO_NL)

        if os.path.exists(socket_dir) and stat.S_IMODE(os.stat(socket_dir).st_mode) == 0o700:
          println('skipped', STATUS)
        else:
          if not os.path.exists(socket_dir):
            os.makedirs(socket_dir)

          os.chmod(socket_dir, 0o700)
          println('done', STATUS)
      except OSError as exc:
        println('failed (%s)' % exc, ERROR)
        raise exc

    # configures logging
    logging_path = CONFIG['integ.log']

    if logging_path:
      logging_path = stem.util.system.expand_path(logging_path, STEM_BASE)
      println('  configuring logger (%s)... ' % logging_path, STATUS, NO_NL)

      # delete the old log

      if os.path.exists(logging_path):
        os.remove(logging_path)

      logging.basicConfig(
        filename = logging_path,
        level = logging.DEBUG,
        format = '%(asctime)s [%(levelname)s] %(message)s',
        datefmt = '%D %H:%M:%S',
      )

      println('done', STATUS)
    else:
      println('  configuring logger... skipped', STATUS)

    # writes our testing torrc
    torrc_dst = os.path.join(self._test_dir, 'torrc')
    try:
      println('  writing torrc (%s)... ' % torrc_dst, STATUS, NO_NL)

      torrc_file = open(torrc_dst, 'w')
      torrc_file.write(self._torrc_contents)
      torrc_file.close()

      println('done', STATUS)

      for line in self._torrc_contents.strip().splitlines():
        println('    %s' % line.strip(), SUBSTATUS)

      println()
    except Exception as exc:
      println('failed (%s)\n' % exc, ERROR)
      raise OSError(exc)

  def _start_tor(self, tor_cmd):
    """
    Initializes a tor process. This blocks until initialization completes or we
    error out.

    :param str tor_cmd: command to start tor with

    :raises: OSError if we either fail to create the tor process or reached a timeout without success
    """

    println('Starting %s...\n' % tor_cmd, STATUS)
    start_time = time.time()

    try:
      # wait to fully complete if we're running tests with network activity,
      # otherwise finish after local bootstraping

      complete_percent = 100 if Target.ONLINE in self.attribute_targets else 5

      def print_init_line(line):
        println('  %s' % line, SUBSTATUS)

      torrc_dst = os.path.join(self._test_dir, 'torrc')
      self._tor_process = stem.process.launch_tor(tor_cmd, None, torrc_dst, complete_percent, print_init_line, take_ownership = True)

      runtime = time.time() - start_time
      println('  done (%i seconds)\n' % runtime, STATUS)
    except OSError as exc:
      println('  failed to start tor: %s\n' % exc, ERROR)
      raise exc
