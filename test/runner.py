# Copyright 2011-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Runtime context for the integration tests. This is used both by the test runner
to start and stop tor, and by the integration tests themselves for information
about the tor test instance they're running against.

::

  RunnerStopped - Runner doesn't have an active tor instance
  TorInaccessable - Tor can't be queried for the information

  exercise_controller - basic sanity check that a controller connection can be used
  get_runner - Singleton for fetching our runtime context.

  Runner - Runtime context for our integration tests.
    |- start - prepares and starts a tor instance for our tests to run against
    |- stop - stops our tor instance and cleans up any temporary files
    |- is_running - checks if our tor test instance is running
    |- is_accessible - checks if our tor instance can be connected to
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
import test

from test.output import println, STATUS, ERROR, SUBSTATUS, NO_NL

CONFIG = stem.util.conf.config_dict('test', {
  'integ.torrc': '',
  'integ.extra_torrc': '',
  'integ.test_directory': './test/data',
  'integ.log': './test/data/log',
  'target.torrc': {},
})

SOCKS_PORT = 1112
ORPORT = 1113

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


class RunnerStopped(Exception):
  "Raised when we try to use a Runner that doesn't have an active tor instance"


class TorInaccessable(Exception):
  'Raised when information is needed from tor but the instance we have is inaccessible'


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
    self.attribute_targets = []

    self._runner_lock = threading.RLock()

    # runtime attributes, set by the start method

    self._test_dir = ''
    self._tor_cmd = None
    self._tor_cwd = ''
    self._torrc_contents = ''
    self._custom_opts = []
    self._tor_process = None
    self._chroot_path = None

    # set if we monkey patch stem.socket.recv_message()

    self._original_recv_message = None

    # The first controller to attach takes ownership so tor will promptly
    # terminate if the tests do. As such we need to ensure that first
    # connection is our runner's.

    self._owner_controller = None

  def start(self, config_target, attribute_targets, tor_cmd):
    """
    Makes temporary testing resources and starts tor, blocking until it
    completes.

    :param str config_target: **Target** for this test run's torrc settings
    :param list attribute_targets: **Targets** for our non-configuration attributes
    :param str tor_cmd: command to start tor with

    :raises: OSError if unable to run test preparations or start tor
    """

    with self._runner_lock:
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
        self._test_dir = stem.util.system.expand_path(config_test_dir, test.STEM_BASE)
      else:
        self._test_dir = tempfile.mktemp('-stem-integ')

      original_cwd, data_dir_path = os.getcwd(), self._test_dir
      self._tor_cmd = stem.util.system.expand_path(tor_cmd) if os.path.sep in tor_cmd else tor_cmd

      if test.Target.RELATIVE in self.attribute_targets:
        tor_cwd = os.path.dirname(self._test_dir)

        if not os.path.exists(tor_cwd):
          os.makedirs(tor_cwd)

        os.chdir(tor_cwd)
        data_dir_path = './%s' % os.path.basename(self._test_dir)

      config_csv = CONFIG['target.torrc'].get(config_target)
      target_torrc_opts = []

      if config_csv:
        for opt in config_csv.split(','):
          opt = opt.strip()

          if opt in Torrc.keys():
            target_torrc_opts.append(Torrc[opt])
          else:
            raise ValueError("'%s' isn't a test.runner.Torrc enumeration" % opt)

      self._custom_opts = target_torrc_opts

      self._torrc_contents = CONFIG['integ.torrc']

      if target_torrc_opts:
        self._torrc_contents += '\n\n# Torrc options for the %s target\n\n' % config_target
        self._torrc_contents += '\n'.join(target_torrc_opts)

      if CONFIG['integ.extra_torrc']:
        self._torrc_contents += '\n\n# Torrc options from %s\n\n' % os.environ['STEM_TEST_CONFIG']
        self._torrc_contents += CONFIG['integ.extra_torrc']

      self._torrc_contents = self._torrc_contents.replace('[DATA_DIR]', data_dir_path)
      self._torrc_contents = self._torrc_contents.replace('[SOCKS_PORT]', str(SOCKS_PORT))
      self._torrc_contents = self._torrc_contents.replace('[OR_PORT]', str(ORPORT))

      try:
        self._tor_cwd = os.getcwd()
        self._run_setup()
        self._start_tor(self._tor_cmd)

        # strip the testing directory from recv_message responses if we're
        # simulating a chroot setup

        if test.Target.CHROOT in self.attribute_targets and not self._original_recv_message:
          # TODO: when we have a function for telling stem the chroot we'll
          # need to set that too

          self._original_recv_message = stem.socket.recv_message
          self._chroot_path = data_dir_path

          def _chroot_recv_message(control_file):
            return self._original_recv_message(_MockChrootFile(control_file, data_dir_path))

          stem.socket.recv_message = _chroot_recv_message

        if self.is_accessible():
          self._owner_controller = self.get_tor_controller(True)

        if test.Target.RELATIVE in self.attribute_targets:
          os.chdir(original_cwd)  # revert our cwd back to normal
      except OSError as exc:
        raise exc

  def stop(self):
    """
    Stops our tor test instance and cleans up any temporary resources.
    """

    with self._runner_lock:
      println('Shutting down tor... ', STATUS, NO_NL)

      if self._owner_controller:
        self._owner_controller.close()
        self._owner_controller = None

      if self._tor_process:
        # if the tor process has stopped on its own then the following raises
        # an OSError ([Errno 3] No such process)

        try:
          self._tor_process.kill()
        except OSError:
          pass

        self._tor_process.stdout.close()
        self._tor_process.stderr.close()

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
      self._custom_opts = []
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

  def get_tor_command(self, base_cmd = False):
    """
    Provides the command used to run our tor instance.

    :param bool base_cmd: provides just the command name if true rather than
      the full '--tor path' argument
    """

    return os.path.basename(self._get('_tor_cmd')) if base_cmd else self._get('_tor_cmd')

  def assert_tor_is_running(self):
    """
    Checks if our tor process is running. If not, this prints an error and
    provides **False**.
    """

    if not self._tor_process:
      println('Tor process failed to initialize', ERROR)
      return False

    process_status = self._tor_process.poll()  # None if running

    if process_status is None:
      return True
    else:
      process_output = stem.util.str_tools._to_unicode(self._tor_process.stdout.read() + b'\n\n' + self._tor_process.stderr.read()).strip()
      println('\n%s\nOur tor process ended prematurely with exit status %s\n%s\n\n%s' % ('=' * 60, process_status, '=' * 60, process_output), ERROR)
      return False

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
      logging_path = stem.util.system.expand_path(logging_path, test.STEM_BASE)
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
      self._tor_process = stem.process.launch_tor(
        tor_cmd = tor_cmd,
        torrc_path = os.path.join(self._test_dir, 'torrc'),
        completion_percent = 100 if test.Target.ONLINE in self.attribute_targets else 0,
        init_msg_handler = lambda line: println('  %s' % line, SUBSTATUS),
        take_ownership = True,
        close_output = False,
      )

      runtime = time.time() - start_time
      println('  done (%i seconds)\n' % runtime, STATUS)
    except OSError as exc:
      println('  failed to start tor: %s\n' % exc, ERROR)
      raise exc
