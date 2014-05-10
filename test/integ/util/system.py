"""
Integration tests for the stem.util.system functions against the tor process
that we're running.
"""

import getpass
import os
import tempfile
import unittest

import stem.util.proc
import stem.util.system
import test.runner

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch


IS_EXTRA_TOR_RUNNING = None


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


def _has_port():
  """
  True if our test runner has a control port, False otherwise.
  """

  return test.runner.Torrc.PORT in test.runner.get_runner().get_options()


class TestSystem(unittest.TestCase):
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

  def test_is_running(self):
    """
    Checks the stem.util.system.is_running function.
    """

    if not stem.util.system.is_available('ps'):
      test.runner.skip(self, '(ps unavailable)')
      return

    self.assertTrue(stem.util.system.is_running('tor'))
    self.assertFalse(stem.util.system.is_running('blarg_and_stuff'))

  def test_get_pid_by_name(self):
    """
    Checks general usage of the stem.util.system.get_pid_by_name function. This
    will fail if there's other tor instances running.
    """

    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return
    elif self._is_extra_tor_running():
      test.runner.skip(self, '(multiple tor instances)')
      return

    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name('tor'))
    self.assertEquals(None, stem.util.system.get_pid_by_name('blarg_and_stuff'))

  def test_get_pid_by_name_pgrep(self):
    """
    Tests the get_pid_by_name function with a pgrep response.
    """

    if self._is_extra_tor_running():
      test.runner.skip(self, '(multiple tor instances)')
      return
    elif not stem.util.system.is_available('pgrep'):
      test.runner.skip(self, '(pgrep unavailable)')
      return

    pgrep_prefix = stem.util.system.GET_PID_BY_NAME_PGREP % ''

    call_replacement = filter_system_call([pgrep_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_name('tor'))

  def test_get_pid_by_name_pidof(self):
    """
    Tests the get_pid_by_name function with a pidof response.
    """

    if self._is_extra_tor_running():
      test.runner.skip(self, '(multiple tor instances)')
      return
    elif not stem.util.system.is_available('pidof'):
      test.runner.skip(self, '(pidof unavailable)')
      return

    pidof_prefix = stem.util.system.GET_PID_BY_NAME_PIDOF % ''

    call_replacement = filter_system_call([pidof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_name('tor'))

  def test_get_pid_by_name_ps_linux(self):
    """
    Tests the get_pid_by_name function with the linux variant of ps.
    """

    if self._is_extra_tor_running():
      test.runner.skip(self, '(multiple tor instances)')
      return
    elif not stem.util.system.is_available('ps'):
      test.runner.skip(self, '(ps unavailable)')
      return
    elif stem.util.system.is_bsd():
      test.runner.skip(self, '(linux only)')
      return

    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_LINUX % ''

    call_replacement = filter_system_call([ps_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_name('tor'))

  def test_get_pid_by_name_ps_bsd(self):
    """
    Tests the get_pid_by_name function with the bsd variant of ps.
    """

    if self._is_extra_tor_running():
      test.runner.skip(self, '(multiple tor instances)')
      return
    elif not stem.util.system.is_available('ps'):
      test.runner.skip(self, '(ps unavailable)')
      return
    elif not stem.util.system.is_bsd():
      test.runner.skip(self, '(bsd only)')
      return

    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_BSD

    call_replacement = filter_system_call([ps_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_name('tor'))

  def test_get_pid_by_name_lsof(self):
    """
    Tests the get_pid_by_name function with a lsof response.
    """

    runner = test.runner.get_runner()
    if self._is_extra_tor_running():
      test.runner.skip(self, '(multiple tor instances)')
      return
    elif not stem.util.system.is_available('lsof'):
      test.runner.skip(self, '(lsof unavailable)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    lsof_prefix = stem.util.system.GET_PID_BY_NAME_LSOF % ''

    call_replacement = filter_system_call([lsof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      our_tor_pid = test.runner.get_runner().get_pid()
      all_tor_pids = stem.util.system.get_pid_by_name('tor', multiple = True)

      if len(all_tor_pids) == 1:
        self.assertEquals(our_tor_pid, all_tor_pids[0])

  def test_get_pid_by_port(self):
    """
    Checks general usage of the stem.util.system.get_pid_by_port function.
    """

    runner = test.runner.get_runner()
    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return
    elif not _has_port():
      test.runner.skip(self, '(test instance has no port)')
      return
    elif stem.util.system.is_mac():
      test.runner.skip(self, '(resolvers unavailable)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return
    elif not (stem.util.system.is_available('netstat') or
              stem.util.system.is_available('sockstat') or
              stem.util.system.is_available('lsof')):
      test.runner.skip(self, '(connection resolvers unavailable)')
      return

    tor_pid, tor_port = runner.get_pid(), test.runner.CONTROL_PORT
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(tor_port))
    self.assertEquals(None, stem.util.system.get_pid_by_port(99999))

  def test_get_pid_by_port_netstat(self):
    """
    Tests the get_pid_by_port function with a netstat response.
    """

    runner = test.runner.get_runner()
    if not _has_port():
      test.runner.skip(self, '(test instance has no port)')
      return
    elif not stem.util.system.is_available('netstat'):
      test.runner.skip(self, '(netstat unavailable)')
      return
    elif stem.util.system.is_bsd() or stem.util.system.is_windows():
      test.runner.skip(self, '(linux only)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    netstat_prefix = stem.util.system.GET_PID_BY_PORT_NETSTAT

    call_replacement = filter_system_call([netstat_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(test.runner.CONTROL_PORT))

  def test_get_pid_by_port_sockstat(self):
    """
    Tests the get_pid_by_port function with a sockstat response.
    """

    runner = test.runner.get_runner()
    if not _has_port():
      test.runner.skip(self, '(test instance has no port)')
      return
    elif not stem.util.system.is_available('sockstat'):
      test.runner.skip(self, '(sockstat unavailable)')
      return
    elif not stem.util.system.is_bsd():
      test.runner.skip(self, '(bsd only)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    sockstat_prefix = stem.util.system.GET_PID_BY_PORT_SOCKSTAT % ''

    call_replacement = filter_system_call([sockstat_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(test.runner.CONTROL_PORT))

  def test_get_pid_by_port_lsof(self):
    """
    Tests the get_pid_by_port function with a lsof response.
    """

    runner = test.runner.get_runner()
    if not _has_port():
      test.runner.skip(self, '(test instance has no port)')
      return
    elif not stem.util.system.is_available('lsof'):
      test.runner.skip(self, '(lsof unavailable)')
      return
    elif stem.util.system.is_mac():
      test.runner.skip(self, '(resolvers unavailable)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    lsof_prefix = stem.util.system.GET_PID_BY_PORT_LSOF

    call_replacement = filter_system_call([lsof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      tor_pid = test.runner.get_runner().get_pid()
      self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(test.runner.CONTROL_PORT))

  def test_get_pid_by_open_file(self):
    """
    Checks the stem.util.system.get_pid_by_open_file function.
    """

    # check a directory that exists, but isn't claimed by any application
    tmpdir = tempfile.mkdtemp()
    self.assertEquals(None, stem.util.system.get_pid_by_open_file(tmpdir))

    # check a directory that doesn't exist
    os.rmdir(tmpdir)
    self.assertEquals(None, stem.util.system.get_pid_by_open_file(tmpdir))

  def test_get_cwd(self):
    """
    Checks general usage of the stem.util.system.get_cwd function.
    """

    runner = test.runner.get_runner()

    if stem.util.system.is_windows():
      test.runner.skip(self, '(unavailable on windows)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEquals(tor_cwd, stem.util.system.get_cwd(runner_pid))
    self.assertEquals(None, stem.util.system.get_cwd(99999))

  def test_get_cwd_pwdx(self):
    """
    Tests the get_pid_by_cwd function with a pwdx response.
    """

    runner = test.runner.get_runner()

    if not stem.util.system.is_available('pwdx'):
      test.runner.skip(self, '(pwdx unavailable)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    # filter the call function to only allow this command

    pwdx_prefix = stem.util.system.GET_CWD_PWDX % ''

    call_replacement = filter_system_call([pwdx_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
      self.assertEquals(tor_cwd, stem.util.system.get_cwd(runner_pid))

  def test_get_cwd_lsof(self):
    """
    Tests the get_pid_by_cwd function with a lsof response.
    """

    runner = test.runner.get_runner()

    if not stem.util.system.is_available('lsof'):
      test.runner.skip(self, '(lsof unavailable)')
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, '(DisableDebuggerAttachment is set)')
      return

    # filter the call function to only allow this command

    lsof_prefix = 'lsof -a -p '

    call_replacement = filter_system_call([lsof_prefix])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
      self.assertEquals(tor_cwd, stem.util.system.get_cwd(runner_pid))

  def test_get_user_none(self):
    """
    Tests the get_user function when the process doesn't exist.
    """

    self.assertEqual(None, stem.util.system.get_user(None))
    self.assertEqual(None, stem.util.system.get_user(-5))
    self.assertEqual(None, stem.util.system.get_start_time(98765))

  def test_get_user_proc(self):
    """
    Tests the get_user function with a proc response.
    """

    if not stem.util.proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return

    call_replacement = filter_system_call(['ps '])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      # we started our tor process so it should be running with the same user

      pid = test.runner.get_runner().get_pid()
      self.assertTrue(getpass.getuser(), stem.util.system.get_user(pid))

  @patch('stem.util.proc.is_available', Mock(return_value = False))
  def test_get_user_ps(self):
    """
    Tests the get_user function with a ps response.
    """

    if not stem.util.system.is_available('ps'):
      test.runner.skip(self, '(ps unavailable)')
      return

    pid = test.runner.get_runner().get_pid()
    self.assertTrue(getpass.getuser(), stem.util.system.get_user(pid))

  def test_get_start_time_none(self):
    """
    Tests the get_start_time function when the process doesn't exist.
    """

    self.assertEqual(None, stem.util.system.get_start_time(None))
    self.assertEqual(None, stem.util.system.get_start_time(-5))
    self.assertEqual(None, stem.util.system.get_start_time(98765))

  def test_get_start_time_proc(self):
    """
    Tests the get_start_time function with a proc response.
    """

    if not stem.util.proc.is_available():
      test.runner.skip(self, '(proc unavailable)')
      return

    call_replacement = filter_system_call(['ps '])

    with patch('stem.util.system.call') as call_mock:
      call_mock.side_effect = call_replacement

      pid = test.runner.get_runner().get_pid()
      self.assertTrue(stem.util.system.get_start_time(pid) >= 0)

  @patch('stem.util.proc.is_available', Mock(return_value = False))
  def test_get_start_time_ps(self):
    """
    Tests the get_start_time function with a ps response.
    """

    if not stem.util.system.is_available('ps'):
      test.runner.skip(self, '(ps unavailable)')
      return

    pid = test.runner.get_runner().get_pid()
    self.assertTrue(stem.util.system.get_start_time(pid) >= 0)

  def test_get_bsd_jail_id(self):
    """
    Exercises the stem.util.system.get_bsd_jail_id function, running through
    the failure case (since I'm not on BSD I can't really test this function
    properly).
    """

    self.assertEquals(0, stem.util.system.get_bsd_jail_id(99999))

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
      test.runner.skip(self, '(running as root)')
      return

    self.assertEquals(os.getcwd(), stem.util.system.expand_path('.'))
    self.assertEquals(os.getcwd(), stem.util.system.expand_path('./'))
    self.assertEquals(os.path.join(os.getcwd(), 'foo'), stem.util.system.expand_path('./foo'))

    home_dir, username = os.path.expanduser('~'), getpass.getuser()
    self.assertEquals(home_dir, stem.util.system.expand_path('~'))
    self.assertEquals(home_dir, stem.util.system.expand_path('~/'))
    self.assertEquals(home_dir, stem.util.system.expand_path('~%s' % username))
    self.assertEquals(os.path.join(home_dir, 'foo'), stem.util.system.expand_path('~%s/foo' % username))

  def test_set_process_name(self):
    """
    Exercises the get_process_name() and set_process_name() methods.
    """

    initial_name = stem.util.system.get_process_name()
    self.assertTrue('run_tests.py' in initial_name)

    try:
      stem.util.system.set_process_name('stem_integ')
      self.assertEqual('stem_integ', stem.util.system.get_process_name())
    finally:
      stem.util.system.set_process_name(initial_name)

  def _is_extra_tor_running(self):
    # Try to figure out if there's more than one tor instance running. This
    # check will fail if pgrep is unavailable (for instance on bsd) but this
    # isn't the end of the world. It's just used to skip tests if they should
    # legitemately fail.

    global IS_EXTRA_TOR_RUNNING

    if IS_EXTRA_TOR_RUNNING is None:
      if stem.util.system.is_windows():
        # TODO: not sure how to check for this on windows
        IS_EXTRA_TOR_RUNNING = False
      elif not stem.util.system.is_bsd():
        pgrep_results = stem.util.system.call(stem.util.system.GET_PID_BY_NAME_PGREP % 'tor')
        IS_EXTRA_TOR_RUNNING = len(pgrep_results) > 1
      else:
        ps_results = stem.util.system.call(stem.util.system.GET_PID_BY_NAME_PS_BSD)
        results = [r for r in ps_results if r.endswith(' tor')]
        IS_EXTRA_TOR_RUNNING = len(results) > 1

    return IS_EXTRA_TOR_RUNNING
