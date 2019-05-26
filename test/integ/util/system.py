"""
Integration tests for the stem.util.system functions against the tor process
that we're running.
"""

import getpass
import os
import tempfile
import unittest

import stem.prereq
import stem.util.proc
import stem.util.system
import test.require
import test.runner

from stem.util.system import State, DaemonTask

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch


def filter_system_call(prefixes):
  """
  Provides a functor that passes calls on to the stem.util.system.call()
  function if it matches one of the prefixes, and acts as a no-op otherwise.
  """

  original_call = stem.util.system.call

  def _filter_system_call(command, default):
    for prefix in prefixes:
      if command.startswith(prefix):
        real_call_function = original_call
        return real_call_function(command)

  return _filter_system_call


def _is_single_tor_running():
  if stem.util.system.is_windows():
    return True  # TODO: not sure how to check for this on windows
  elif not stem.util.system.is_bsd():
    tor_cmd = test.runner.get_runner().get_tor_command(True)
    pgrep_results = stem.util.system.call(stem.util.system.GET_PID_BY_NAME_PGREP % tor_cmd)
    return len(pgrep_results) == 1
  else:
    ps_results = stem.util.system.call(stem.util.system.GET_PID_BY_NAME_PS_BSD)
    results = [r for r in ps_results if r.endswith(' tor')]
    return len(results) == 1


def _is_linux():
  return not stem.util.system.is_bsd() and not stem.util.system.is_windows()


def _has_port():
  """
  True if our test runner has a control port, False otherwise.
  """

  return test.runner.Torrc.PORT in test.runner.get_runner().get_options()


require_control_port = test.require.needs(_has_port, 'test instance has no port')
require_linux = test.require.needs(_is_linux, 'linux only')
require_bsd = test.require.needs(stem.util.system.is_bsd, 'bsd only')
require_path = test.require.needs(lambda: 'PATH' in os.environ, 'requires PATH')


def require_single_tor_instance(func):
  # Checking both before and after the test to see if we're running only a
  # single tor instance. We do both to narrow the possability of the test
  # failing due to a race.

  def wrapped(self, *args, **kwargs):
    if _is_single_tor_running():
      try:
        return func(self, *args, **kwargs)
      except:
        if _is_single_tor_running():
          raise
        else:
          self.skipTest('(multiple tor instances)')
    else:
      self.skipTest('(multiple tor instances)')

  return wrapped


class TestSystem(unittest.TestCase):
  def test_daemon_task_when_successful(self):
    """
    Checks a simple, successfully DaemonTask that simply echos a value.
    """

    task = DaemonTask(lambda arg: arg, ('hello world',))

    self.assertEqual(None, task.result)
    self.assertEqual(State.PENDING, task.status)

    task.run()
    self.assertEqual('hello world', task.join())
    self.assertEqual(State.DONE, task.status)
    self.assertTrue(0 < task.runtime < 1.0)

  def test_daemon_task_on_failure(self):
    """
    Checks DaemonTask when an exception is raised.
    """

    def _test_task(arg):
      raise RuntimeError(arg)

    task = DaemonTask(_test_task, ('hello world',))

    self.assertEqual(None, task.result)
    self.assertEqual(State.PENDING, task.status)

    task.run()
    self.assertRaisesWith(RuntimeError, 'hello world', task.join)
    self.assertEqual(State.FAILED, task.status)
    self.assertTrue(0 < task.runtime < 1.0)

  @require_path
  def test_is_available(self):
    """
    Checks the stem.util.system.is_available function.
    """

    # I have yet to see a platform without 'ls'

    if stem.util.system.is_windows():
      self.assertTrue(stem.util.system.is_available('dir'))
    else:
      self.assertTrue(stem.util.system.is_available('ls'))

    # but it would be kinda weird if this did...

    self.assertFalse(stem.util.system.is_available('blarg_and_stuff'))

  def test_is_running_by_pid(self):
    """
    Checks the stem.util.system.is_running function with a pid.
    """

    self.assertTrue(stem.util.system.is_running(test.runner.get_runner().get_pid()))
    self.assertFalse(stem.util.system.is_running(528955))

  @test.require.command('ps')
  def test_is_running_by_name(self):
    """
    Checks the stem.util.system.is_running function with a process name.
    """

    # Check to see if the command we started tor with is running. The process
    # might be running under another name so need to check for 'tor.real' too
    # (#15449).

    tor_cmd = test.runner.get_runner().get_tor_command(True)
    self.assertTrue(stem.util.system.is_running(tor_cmd) or stem.util.system.is_running('tor.real'))
    self.assertFalse(stem.util.system.is_running('blarg_and_stuff'))

  @require_path
  @require_single_tor_instance
  def test_pid_by_name(self):
    """
    Checks general usage of the stem.util.system.pid_by_name function. This
    will fail if there's other tor instances running.
    """

    tor_pid = test.runner.get_runner().get_pid()
    tor_cmd = test.runner.get_runner().get_tor_command(True)
    self.assertEqual(tor_pid, stem.util.system.pid_by_name(tor_cmd))
    self.assertEqual(None, stem.util.system.pid_by_name('blarg_and_stuff'))

  @require_single_tor_instance
  @test.require.command('pgrep')
  def test_pid_by_name_pgrep(self):
    """
    Tests the pid_by_name function with a pgrep response.
    """

    pgrep_prefix = stem.util.system.GET_PID_BY_NAME_PGREP % ''
    call_replacement = filter_system_call([pgrep_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      tor_cmd = test.runner.get_runner().get_tor_command(True)
      self.assertEqual(tor_pid, stem.util.system.pid_by_name(tor_cmd))

  @require_single_tor_instance
  @test.require.command('pidof')
  def test_pid_by_name_pidof(self):
    """
    Tests the pid_by_name function with a pidof response.
    """

    pidof_prefix = stem.util.system.GET_PID_BY_NAME_PIDOF % ''
    call_replacement = filter_system_call([pidof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      tor_cmd = test.runner.get_runner().get_tor_command()
      self.assertEqual(tor_pid, stem.util.system.pid_by_name(tor_cmd))

  @require_linux
  @require_single_tor_instance
  @test.require.command('ps')
  def test_pid_by_name_ps_linux(self):
    """
    Tests the pid_by_name function with the linux variant of ps.
    """

    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_LINUX % ''
    call_replacement = filter_system_call([ps_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      tor_cmd = test.runner.get_runner().get_tor_command(True)
      self.assertEqual(tor_pid, stem.util.system.pid_by_name(tor_cmd))

  @require_bsd
  @require_single_tor_instance
  @test.require.command('ps')
  def test_pid_by_name_ps_bsd(self):
    """
    Tests the pid_by_name function with the bsd variant of ps.
    """

    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_BSD
    call_replacement = filter_system_call([ps_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      tor_cmd = test.runner.get_runner().get_tor_command(True)
      self.assertEqual(tor_pid, stem.util.system.pid_by_name(tor_cmd))

  @require_single_tor_instance
  @test.require.ptrace
  @test.require.command('lsof')
  def test_pid_by_name_lsof(self):
    """
    Tests the pid_by_name function with a lsof response.
    """

    lsof_prefix = stem.util.system.GET_PID_BY_NAME_LSOF % ''
    call_replacement = filter_system_call([lsof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_cmd = test.runner.get_runner().get_tor_command(True)
      our_tor_pid = test.runner.get_runner().get_pid()
      all_tor_pids = stem.util.system.pid_by_name(tor_cmd, multiple = True)

      if len(all_tor_pids) == 1:
        self.assertEqual(our_tor_pid, all_tor_pids[0])

  @require_single_tor_instance
  @test.require.command('tasklist')
  def test_pid_by_name_tasklist(self):
    """
    Tests the pid_by_name function with a tasklist response.
    """

    runner = test.runner.get_runner()
    self.assertEqual(runner.get_pid(), stem.util.system.pid_by_name(runner.get_tor_command(True)))

  @require_control_port
  @test.require.ptrace
  def test_pid_by_port(self):
    """
    Checks general usage of the stem.util.system.pid_by_port function.
    """

    if stem.util.system.is_windows():
      self.skipTest('(unavailable on windows)')
      return
    elif stem.util.system.is_mac() or stem.util.system.is_gentoo():
      self.skipTest('(resolvers unavailable)')
      return
    elif not stem.util.system.is_available('netstat') or \
             stem.util.system.is_available('sockstat') or \
              stem.util.system.is_available('lsof'):
      self.skipTest('(connection resolvers unavailable)')
      return

    runner = test.runner.get_runner()
    tor_pid, tor_port = runner.get_pid(), test.runner.CONTROL_PORT
    self.assertEqual(tor_pid, stem.util.system.pid_by_port(tor_port))
    self.assertEqual(None, stem.util.system.pid_by_port(99999))

  @require_linux
  @require_control_port
  @test.require.ptrace
  @test.require.command('netstat')
  def test_pid_by_port_netstat(self):
    """
    Tests the pid_by_port function with a netstat response.
    """

    if stem.util.system.is_gentoo():
      self.skipTest('(unavailable on gentoo)')
      return

    netstat_prefix = stem.util.system.GET_PID_BY_PORT_NETSTAT

    call_replacement = filter_system_call([netstat_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEqual(tor_pid, stem.util.system.pid_by_port(test.runner.CONTROL_PORT))

  @require_bsd
  @require_control_port
  @test.require.ptrace
  @test.require.command('sockstat')
  def test_pid_by_port_sockstat(self):
    """
    Tests the pid_by_port function with a sockstat response.
    """

    sockstat_prefix = stem.util.system.GET_PID_BY_PORT_SOCKSTAT % ''
    call_replacement = filter_system_call([sockstat_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEqual(tor_pid, stem.util.system.pid_by_port(test.runner.CONTROL_PORT))

  @require_control_port
  @test.require.ptrace
  @test.require.command('lsof')
  def test_pid_by_port_lsof(self):
    """
    Tests the pid_by_port function with a lsof response.
    """

    if stem.util.system.is_mac() or stem.util.system.is_gentoo():
      self.skipTest('(resolvers unavailable)')
      return

    lsof_prefix = stem.util.system.GET_PID_BY_PORT_LSOF

    call_replacement = filter_system_call([lsof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEqual(tor_pid, stem.util.system.pid_by_port(test.runner.CONTROL_PORT))

  def test_pid_by_open_file(self):
    """
    Checks the stem.util.system.pid_by_open_file function.
    """

    # check a directory that exists, but isn't claimed by any application
    tmpdir = tempfile.mkdtemp()
    self.assertEqual(None, stem.util.system.pid_by_open_file(tmpdir))

    # check a directory that doesn't exist
    os.rmdir(tmpdir)
    self.assertEqual(None, stem.util.system.pid_by_open_file(tmpdir))

  @require_path
  def test_pids_by_user(self):
    """
    Checks the stem.util.system.pids_by_user function.
    """

    # our own pid should be among the processes for our user

    pids = stem.util.system.pids_by_user(getpass.getuser())
    self.assertTrue(os.getpid() in pids)

  @test.require.ptrace
  def test_cwd(self):
    """
    Checks general usage of the stem.util.system.cwd function.
    """

    if stem.util.system.is_windows():
      self.skipTest('(unavailable on windows)')
      return

    runner = test.runner.get_runner()
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEqual(tor_cwd, stem.util.system.cwd(runner_pid))
    self.assertEqual(None, stem.util.system.cwd(99999))

  @test.require.ptrace
  @test.require.command('pwdx')
  def test_cwd_pwdx(self):
    """
    Tests the pid_by_cwd function with a pwdx response.
    """

    # filter the call function to only allow this command

    pwdx_prefix = stem.util.system.GET_CWD_PWDX % ''

    call_replacement = filter_system_call([pwdx_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      runner = test.runner.get_runner()
      runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
      self.assertEqual(tor_cwd, stem.util.system.cwd(runner_pid))

  @test.require.ptrace
  @test.require.command('lsof')
  def test_cwd_lsof(self):
    """
    Tests the pid_by_cwd function with a lsof response.
    """

    # filter the call function to only allow this command

    lsof_prefix = 'lsof -a -p '

    call_replacement = filter_system_call([lsof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      runner = test.runner.get_runner()
      runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
      self.assertEqual(tor_cwd, stem.util.system.cwd(runner_pid))

  def test_user_none(self):
    """
    Tests the user function when the process doesn't exist.
    """

    self.assertEqual(None, stem.util.system.user(None))
    self.assertEqual(None, stem.util.system.user(-5))
    self.assertEqual(None, stem.util.system.start_time(98765))

  @test.require.proc
  def test_user_proc(self):
    """
    Tests the user function with a proc response.
    """

    call_replacement = filter_system_call(['ps '])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      # we started our tor process so it should be running with the same user

      pid = test.runner.get_runner().get_pid()
      self.assertTrue(getpass.getuser(), stem.util.system.user(pid))

  @test.require.command('ps')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  def test_user_ps(self):
    """
    Tests the user function with a ps response.
    """

    pid = test.runner.get_runner().get_pid()
    self.assertTrue(getpass.getuser(), stem.util.system.user(pid))

  def test_start_time_none(self):
    """
    Tests the start_time function when the process doesn't exist.
    """

    self.assertEqual(None, stem.util.system.start_time(None))
    self.assertEqual(None, stem.util.system.start_time(-5))
    self.assertEqual(None, stem.util.system.start_time(98765))

  @test.require.proc
  def test_start_time_proc(self):
    """
    Tests the start_time function with a proc response.
    """

    call_replacement = filter_system_call(['ps '])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      pid = test.runner.get_runner().get_pid()
      self.assertTrue(stem.util.system.start_time(pid) >= 0)

  @test.require.command('ps')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  def test_start_time_ps(self):
    """
    Tests the start_time function with a ps response.
    """

    pid = test.runner.get_runner().get_pid()
    self.assertTrue(stem.util.system.start_time(pid) >= 0)

  def test_bsd_jail_id(self):
    """
    Exercises the stem.util.system.bsd_jail_id function, running through
    the failure case (since I'm not on BSD I can't really test this function
    properly).
    """

    self.assertEqual(0, stem.util.system.bsd_jail_id(99999))

  def test_expand_path(self):
    """
    Exercises the expand_path() method with actual runtime data.
    """

    # Some of the following tests get confused when ran as root. For instance,
    # in my case...
    #
    #   >>> os.path.expanduser('~')
    #   '/home/atagar'
    #
    #   >>> os.path.expanduser('~root')
    #   '/root'

    if getpass.getuser() == 'root':
      self.skipTest('(running as root)')
      return

    self.assertEqual(os.getcwd(), stem.util.system.expand_path('.'))
    self.assertEqual(os.getcwd(), stem.util.system.expand_path('./'))
    self.assertEqual(os.path.join(os.getcwd(), 'foo'), stem.util.system.expand_path('./foo'))

    home_dir, username = os.path.expanduser('~'), getpass.getuser()
    self.assertEqual(home_dir, stem.util.system.expand_path('~'))
    self.assertEqual(home_dir, stem.util.system.expand_path('~/'))
    self.assertEqual(home_dir, stem.util.system.expand_path('~%s' % username))
    self.assertEqual(os.path.join(home_dir, 'foo'), stem.util.system.expand_path('~%s/foo' % username))

  def test_call_timeout(self):
    self.assertRaisesWith(stem.util.system.CallTimeoutError, "Process didn't finish after 0.0 seconds", stem.util.system.call, 'sleep 1', timeout = 0.001)

  def test_call_time_tracked(self):
    """
    Check that time taken in the call() function is tracked by SYSTEM_CALL_TIME.
    """

    initial = stem.util.system.SYSTEM_CALL_TIME
    stem.util.system.call('sleep 0.005')
    self.assertTrue(stem.util.system.SYSTEM_CALL_TIME - initial > 0.004)

  def test_set_process_name(self):
    """
    Exercises the get_process_name() and set_process_name() methods.
    """

    if stem.prereq.is_pypy():
      self.skipTest('(unimplemented for pypy)')
      return

    initial_name = stem.util.system.get_process_name()
    self.assertTrue('run_tests.py' in initial_name)

    try:
      stem.util.system.set_process_name('stem_integ')
      self.assertEqual('stem_integ', stem.util.system.get_process_name())
    finally:
      stem.util.system.set_process_name(initial_name)
