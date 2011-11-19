"""
Integration tests for the stem.util.system functions in the context of a tor
process.
"""

import os
import getpass
import unittest

import test.runner
import stem.util.system

class TestSystem(unittest.TestCase):
  """
  Tests the stem.util.system functions against the tor process that we're
  running.
  """
  
  def tearDown(self):
    # resets call mocking back to being disabled
    stem.util.system.CALL_MOCKING = None
  
  def test_is_available(self):
    """
    Checks the stem.util.system.is_available function.
    """
    
    # since we're running tor it would be kinda sad if this didn't detect it
    self.assertTrue(stem.util.system.is_available("tor"))
    
    # but it would be kinda weird if this did...
    self.assertFalse(stem.util.system.is_available("blarg_and_stuff"))
  
  def test_is_running(self):
    """
    Checks the stem.util.system.is_running function.
    """
    
    self.assertTrue(stem.util.system.is_running("tor"))
    self.assertFalse(stem.util.system.is_running("blarg_and_stuff"))
  
  def test_get_pid_by_name(self):
    """
    Checks general usage of the stem.util.system.get_pid_by_name function. This
    will fail if there's other tor instances running.
    """
    
    runner = test.runner.get_runner()
    self.assertEquals(runner.get_pid(), stem.util.system.get_pid_by_name("tor"))
    self.assertEquals(None, stem.util.system.get_pid_by_name("blarg_and_stuff"))
  
  def test_get_pid_by_name_pgrep(self):
    """
    Tests the get_pid_by_name function with a pgrep response.
    """
    
    if not stem.util.system.is_available("pgrep"):
      self.skipTest("(pgrep unavailable)")
    
    pgrep_prefix = stem.util.system.GET_PID_BY_NAME_PGREP % ""
    self._run_pid_test(pgrep_prefix, stem.util.system.get_pid_by_name, "tor")
  
  def test_get_pid_by_name_pidof(self):
    """
    Tests the get_pid_by_name function with a pidof response.
    """
    
    if not stem.util.system.is_available("pidof"):
      self.skipTest("(pidof unavailable)")
    
    pidof_prefix = stem.util.system.GET_PID_BY_NAME_PIDOF % ""
    self._run_pid_test(pidof_prefix, stem.util.system.get_pid_by_name, "tor")
  
  def test_get_pid_by_name_ps_linux(self):
    """
    Tests the get_pid_by_name function with the linux variant of ps.
    """
    
    if not stem.util.system.is_available("ps"):
      self.skipTest("(ps unavailable)")
    elif stem.util.system.is_bsd(): self.skipTest("(linux only)")
    
    ps_prefix = stem.util.system.GET_PID_BY_NAME_PS_LINUX % ""
    self._run_pid_test(ps_prefix, stem.util.system.get_pid_by_name, "tor")
  
  def test_get_pid_by_name_ps_bsd(self):
    """
    Tests the get_pid_by_name function with the bsd variant of ps.
    """
    
    if not stem.util.system.is_available("ps"):
      self.skipTest("(ps unavailable)")
    elif not stem.util.system.is_bsd(): self.skipTest("(bsd only)")
    
    ps_cmd = stem.util.system.GET_PID_BY_NAME_PS_BSD
    self._run_pid_test(ps_cmd, stem.util.system.get_pid_by_name, "tor")
  
  def test_get_pid_by_name_lsof(self):
    """
    Tests the get_pid_by_name function with a lsof response.
    """
    
    if not stem.util.system.is_available("lsof"):
      self.skipTest("(lsof unavailable)")
    
    lsof_prefix = stem.util.system.GET_PID_BY_NAME_LSOF % ""
    self._run_pid_test(lsof_prefix, stem.util.system.get_pid_by_name, "tor")
  
  def test_get_pid_by_port(self):
    """
    Checks general usage of the stem.util.system.get_pid_by_port function.
    """
    
    runner = test.runner.get_runner()
    tor_pid, tor_port = runner.get_pid(), runner.get_control_port()
    self.assertEquals(tor_pid, stem.util.system.get_pid_by_port(tor_port))
    self.assertEquals(None, stem.util.system.get_pid_by_port(99999))
  
  def test_get_pid_by_port_netstat(self):
    """
    Tests the get_pid_by_port function with a netstat response.
    """
    
    if not stem.util.system.is_available("netstat"):
      self.skipTest("(netstat unavailable)")
    elif stem.util.system.is_bsd(): self.skipTest("(linux only)")
    
    netstat_cmd = stem.util.system.GET_PID_BY_PORT_NETSTAT
    runner_port = test.runner.get_runner().get_control_port()
    self._run_pid_test(netstat_cmd, stem.util.system.get_pid_by_port, runner_port)
  
  def test_get_pid_by_port_sockstat(self):
    """
    Tests the get_pid_by_port function with a sockstat response.
    """
    
    if not stem.util.system.is_available("sockstat"):
      self.skipTest("(sockstat unavailable)")
    elif not stem.util.system.is_bsd(): self.skipTest("(bsd only)")
    
    sockstat_prefix = stem.util.system.GET_PID_BY_PORT_SOCKSTAT % ""
    runner_port = test.runner.get_runner().get_control_port()
    self._run_pid_test(sockstat_prefix, stem.util.system.get_pid_by_port, runner_port)
  
  def test_get_pid_by_port_lsof(self):
    """
    Tests the get_pid_by_port function with a lsof response.
    """
    
    if not stem.util.system.is_available("lsof"):
      self.skipTest("(lsof unavailable)")
    
    lsof_cmd = stem.util.system.GET_PID_BY_PORT_LSOF
    runner_port = test.runner.get_runner().get_control_port()
    self._run_pid_test(lsof_cmd, stem.util.system.get_pid_by_port, runner_port)
  
  def test_get_pid_by_open_file(self):
    """
    Checks the stem.util.system.get_pid_by_open_file function.
    """
    
    # we're not running with a control socket so this just exercises the
    # failure case
    
    self.assertEquals(None, stem.util.system.get_pid_by_open_file("/tmp"))
    self.assertEquals(None, stem.util.system.get_pid_by_open_file("/non-existnt-path"))
  
  def test_get_cwd(self):
    """
    Checks general usage of the stem.util.system.get_cwd function.
    """
    
    # tor's pwd will match our process since we started it
    runner = test.runner.get_runner()
    self.assertEquals(os.getcwd(), stem.util.system.get_cwd(runner.get_pid()))
    self.assertEquals(None, stem.util.system.get_cwd(99999))
  
  def test_get_cwd_pwdx(self):
    """
    Tests the get_pid_by_cwd function with a pwdx response.
    """
    
    if not stem.util.system.is_available("pwdx"):
      self.skipTest("(pwdx unavailable)")
    
    # filter the call function to only allow this command
    pwdx_prefix = GET_CWD_PWDX % ""
    stem.util.system.CALL_MOCKING = lambda cmd: cmd.startswith(pwdx_prefix)
    
    runner_pid = test.runner.get_runner().get_pid()
    self.assertEquals(os.getcwd(), stem.util.system.get_cwd(runner_pid))
  
  def test_get_cwd_pwdx(self):
    """
    Tests the get_pid_by_cwd function with a lsof response.
    """
    
    if not stem.util.system.is_available("lsof"):
      self.skipTest("(lsof unavailable)")
    
    # filter the call function to only allow this command
    lsof_prefix = "lsof -a -p "
    stem.util.system.CALL_MOCKING = lambda cmd: cmd.startswith(lsof_prefix)
    
    runner_pid = test.runner.get_runner().get_pid()
    self.assertEquals(os.getcwd(), stem.util.system.get_cwd(runner_pid))
  
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
    
    home_dir, username = os.getenv("HOME"), getpass.getuser()
    self.assertEquals(home_dir, stem.util.system.expand_path("~"))
    self.assertEquals(home_dir, stem.util.system.expand_path("~/"))
    self.assertEquals(home_dir, stem.util.system.expand_path("~%s" % username))
    self.assertEquals(os.path.join(home_dir, "foo"), stem.util.system.expand_path("~%s/foo" % username))
  
  def _run_pid_test(self, cmd_prefix, test_function, arg):
    """
    Runs a get_pid_by_* test with the given inputs.
    """
    
    # filter the call function to only allow this command
    stem.util.system.CALL_MOCKING = lambda cmd: cmd.startswith(cmd_prefix)
    
    runner_pid = test.runner.get_runner().get_pid()
    self.assertEquals(runner_pid, test_function(arg))

