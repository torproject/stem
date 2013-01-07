"""
Integration tests for the stem.util.system functions against the tor process
that we're running.
"""

import getpass
import os
import tempfile
import unittest

import stem.util.system
import test.runner

from test import mocking

def filter_system_call(prefixes):
  """
  Provides a functor that passes calls on to the stem.util.system.call()
  function if it matches one of the prefixes, and acts as a no-op otherwise.
  """
  
  def _filter_system_call(command):
    for prefix in prefixes:
      if command.startswith(prefix):
        real_call_function = mocking.get_real_function(stem.util.system.call)
        return real_call_function(command)
  
  return _filter_system_call

def _has_port():
  """
  True if our test runner has a control port, False otherwise.
  """
  
  return test.runner.Torrc.PORT in test.runner.get_runner().get_options()

class TestSystem(unittest.TestCase):
  is_extra_tor_running = None
  
  def setUp(self):
    # Try to figure out if there's more than one tor instance running. This
    # check will fail if pgrep is unavailable (for instance on bsd) but this
    # isn't the end of the world. It's just used to skip tests if they should
    # legitemately fail.
    
    if self.is_extra_tor_running is None:
      if stem.util.system.is_windows():
        # TODO: not sure how to check for this on windows
        self.is_extra_tor_running = False
      elif not stem.util.system.is_bsd():
        pgrep_results = stem.util.system.call(stem.util.system.GET_PID_BY_NAME_PGREP % "tor")
        self.is_extra_tor_running = len(pgrep_results) > 1
      else:
        ps_results = stem.util.system.call(stem.util.system.GET_PID_BY_NAME_PS_BSD)
        results = [r for r in ps_results if r.endswith(" tor")]
        self.is_extra_tor_running = len(results) > 1
  
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_is_available(self):
    """
    Checks the stem.util.system.is_available function.
    """
    
    # I have yet to see a platform without 'ls'
    if stem.util.system.is_windows():
      self.assertTrue(stem.util.system.is_available("dir"))
    else:
      self.assertTrue(stem.util.system.is_available("ls"))
    
    # but it would be kinda weird if this did...
    self.assertFalse(stem.util.system.is_available("blarg_and_stuff"))
  
  def test_is_running(self):
    """
    Checks the stem.util.system.is_running function.
    """
    
    if not stem.util.system.is_available("ps"):
      test.runner.skip(self, "(ps unavailable)")
      return
    
    self.assertTrue(stem.util.system.is_running("tor"))
    self.assertFalse(stem.util.system.is_running("blarg_and_stuff"))
  
  def test_get_pid_by_name(self):
    """
    Checks general usage of the stem.util.system.get_pid_by_name function. This
    will fail if there's other tor instances running.
    """
    
    if stem.util.system.is_windows():
      test.runner.skip(self, "(unavailable on windows)")
      return
    elif self.is_extra_tor_running:
      test.runner.skip(self, "(multiple tor instances)")
      return
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name("tor"))
    self.assertEquals(None, stem.util.system.get_pid_by_name("blarg_and_stuff"))
  
  def test_get_pid_by_name_pgrep(self):
    """
    Tests the get_pid_by_name function with a pgrep response.
    """
    
    if self.is_extra_tor_running:
      test.runner.skip(self, "(multiple tor instances)")
      return
    elif not stem.util.system.is_available("pgrep"):
      test.runner.skip(self, "(pgrep unavailable)")
      return
    
    pgrep_prefix = stem.util.system.GET_PID_BY_NAME_PGREP % ""
    mocking.mock(stem.util.system.call, filter_system_call([pgrep_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name("tor"))
  
  def test_get_pid_by_name_pidof(self):
    """
    Tests the get_pid_by_name function with a pidof response.
    """
    
    if self.is_extra_tor_running:
      test.runner.skip(self, "(multiple tor instances)")
      return
    elif not stem.util.system.is_available("pidof"):
      test.runner.skip(self, "(pidof unavailable)")
      return
    
    pidof_prefix = stem.util.system.GET_PID_BY_NAME_PIDOF % ""
    mocking.mock(stem.util.system.call, filter_system_call([pidof_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name("tor"))
  
  def test_get_pid_by_name_ps_linux(self):
    """
    Tests the get_pid_by_name function with the linux variant of ps.
    """
    
    if self.is_extra_tor_running:
      test.runner.skip(self, "(multiple tor instances)")
      return
    elif not stem.util.system.is_available("ps"):
      test.runner.skip(self, "(ps unavailable)")
      return
    elif stem.util.system.is_bsd():
      test.runner.skip(self, "(linux only)")
      return
    
    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_LINUX % ""
    mocking.mock(stem.util.system.call, filter_system_call([ps_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name("tor"))
  
  def test_get_pid_by_name_ps_bsd(self):
    """
    Tests the get_pid_by_name function with the bsd variant of ps.
    """
    
    if self.is_extra_tor_running:
      test.runner.skip(self, "(multiple tor instances)")
      return
    elif not stem.util.system.is_available("ps"):
      test.runner.skip(self, "(ps unavailable)")
      return
    elif not stem.util.system.is_bsd():
      test.runner.skip(self, "(bsd only)")
      return
    
    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_BSD
    mocking.mock(stem.util.system.call, filter_system_call([ps_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name("tor"))
  
  def test_get_pid_by_name_lsof(self):
    """
    Tests the get_pid_by_name function with a lsof response.
    """
    
    runner = test.runner.get_runner()
    if self.is_extra_tor_running:
      test.runner.skip(self, "(multiple tor instances)")
      return
    elif not stem.util.system.is_available("lsof"):
      test.runner.skip(self, "(lsof unavailable)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    lsof_prefix = stem.util.system.GET_PID_BY_NAME_LSOF % ""
    mocking.mock(stem.util.system.call, filter_system_call([lsof_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_name("tor"))
  
  def test_get_pid_by_port(self):
    """
    Checks general usage of the stem.util.system.get_pid_by_port function.
    """
    
    runner = test.runner.get_runner()
    if stem.util.system.is_windows():
      test.runner.skip(self, "(unavailable on windows)")
      return
    elif not _has_port():
      test.runner.skip(self, "(test instance has no port)")
      return
    elif stem.util.system.is_mac():
      test.runner.skip(self, "(resolvers unavailable)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
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
      test.runner.skip(self, "(test instance has no port)")
      return
    elif not stem.util.system.is_available("netstat"):
      test.runner.skip(self, "(netstat unavailable)")
      return
    elif stem.util.system.is_bsd() or stem.util.system.is_windows():
      test.runner.skip(self, "(linux only)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    netstat_prefix = stem.util.system.GET_PID_BY_PORT_NETSTAT
    mocking.mock(stem.util.system.call, filter_system_call([netstat_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(test.runner.CONTROL_PORT))
  
  def test_get_pid_by_port_sockstat(self):
    """
    Tests the get_pid_by_port function with a sockstat response.
    """
    
    runner = test.runner.get_runner()
    if not _has_port():
      test.runner.skip(self, "(test instance has no port)")
      return
    elif not stem.util.system.is_available("sockstat"):
      test.runner.skip(self, "(sockstat unavailable)")
      return
    elif not stem.util.system.is_bsd():
      test.runner.skip(self, "(bsd only)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    sockstat_prefix = stem.util.system.GET_PID_BY_PORT_SOCKSTAT % ""
    mocking.mock(stem.util.system.call, filter_system_call([sockstat_prefix]))
    
    tor_pid = test.runner.get_runner().get_pid()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(test.runner.CONTROL_PORT))
  
  def test_get_pid_by_port_lsof(self):
    """
    Tests the get_pid_by_port function with a lsof response.
    """
    
    runner = test.runner.get_runner()
    if not _has_port():
      test.runner.skip(self, "(test instance has no port)")
      return
    elif not stem.util.system.is_available("lsof"):
      test.runner.skip(self, "(lsof unavailable)")
      return
    elif stem.util.system.is_mac():
      test.runner.skip(self, "(resolvers unavailable)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    lsof_prefix = stem.util.system.GET_PID_BY_PORT_LSOF
    mocking.mock(stem.util.system.call, filter_system_call([lsof_prefix]))
    
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
      test.runner.skip(self, "(unavailable on windows)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEquals(tor_cwd, stem.util.system.get_cwd(runner_pid))
    self.assertEquals(None, stem.util.system.get_cwd(99999))
  
  def test_get_cwd_pwdx(self):
    """
    Tests the get_pid_by_cwd function with a pwdx response.
    """
    
    runner = test.runner.get_runner()
    if not stem.util.system.is_available("pwdx"):
      test.runner.skip(self, "(pwdx unavailable)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    # filter the call function to only allow this command
    pwdx_prefix = stem.util.system.GET_CWD_PWDX % ""
    mocking.mock(stem.util.system.call, filter_system_call([pwdx_prefix]))
    
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEquals(tor_cwd, stem.util.system.get_cwd(runner_pid))
  
  def test_get_cwd_lsof(self):
    """
    Tests the get_pid_by_cwd function with a lsof response.
    """
    
    runner = test.runner.get_runner()
    if not stem.util.system.is_available("lsof"):
      test.runner.skip(self, "(lsof unavailable)")
      return
    elif not runner.is_ptraceable():
      test.runner.skip(self, "(DisableDebuggerAttachment is set)")
      return
    
    # filter the call function to only allow this command
    lsof_prefix = "lsof -a -p "
    mocking.mock(stem.util.system.call, filter_system_call([lsof_prefix]))
    
    runner_pid, tor_cwd = runner.get_pid(), runner.get_tor_cwd()
    self.assertEquals(tor_cwd, stem.util.system.get_cwd(runner_pid))
  
  def test_get_bsd_jail_id(self):
    """
    Exercises the stem.util.system.get_bsd_jail_id function, running through
    the failure case (since I'm not on BSD I can't really test this function
    properly).
    """
    
    self.assertEquals(0, stem.util.system.get_bsd_jail_id(99999))
  
  def test_expand_path(self):
    """
    Exercises the stem.expand_path method with actual runtime data.
    """
    
    self.assertEquals(os.getcwd(), stem.util.system.expand_path("."))
    self.assertEquals(os.getcwd(), stem.util.system.expand_path("./"))
    self.assertEquals(os.path.join(os.getcwd(), "foo"), stem.util.system.expand_path("./foo"))
    
    home_dir, username = os.path.expanduser("~"), getpass.getuser()
    self.assertEquals(home_dir, stem.util.system.expand_path("~"))
    self.assertEquals(home_dir, stem.util.system.expand_path("~/"))
    self.assertEquals(home_dir, stem.util.system.expand_path("~%s" % username))
    self.assertEquals(os.path.join(home_dir, "foo"), stem.util.system.expand_path("~%s/foo" % username))
