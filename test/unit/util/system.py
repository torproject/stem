"""
Unit tests for the stem.util.system functions. This works by mocking the
stem.util.system.call function to selectively exercise other functions. None of
these tests actually make system calls, use proc, or otherwise deal with the
system running the tests.
"""

import functools
import ntpath
import os
import platform
import posixpath
import unittest

import stem.util.proc

from stem.util import system
from test import mocking

# Base responses for the get_pid_by_name tests. The 'success' and
# 'multiple_results' entries are filled in by tests.

GET_PID_BY_NAME_BASE_RESULTS = {
  "success": [],
  "multiple_results": [],
  "malformed_data": ["bad data"],
  "no_results": [],
  "command_fails": None,
}

# testing output for system calls

GET_PID_BY_NAME_PS_BSD = [
  "  PID   TT  STAT      TIME COMMAND",
  "    1   ??  Ss     9:00.22 launchd",
  "   10   ??  Ss     0:09.97 kextd",
  "   11   ??  Ss     5:47.36 DirectoryService",
  "   12   ??  Ss     3:01.44 notifyd"]

GET_PID_BY_PORT_NETSTAT_RESULTS = [
  "Active Internet connections (only servers)",
  "Proto Recv-Q Send-Q Local Address           Foreign Address   State    PID/Program name",
  "tcp        0      0 127.0.0.1:631           0.0.0.0:*         LISTEN   -     ",
  "tcp        0      0 127.0.0.1:9051          0.0.0.0:*         LISTEN   1641/tor  ",
  "tcp6       0      0 ::1:631                 :::*              LISTEN   -     ",
  "udp        0      0 0.0.0.0:5353            0.0.0.0:*                  -     ",
  "udp6       0      0 fe80::7ae4:ff:fe2f::123 :::*                       -     "]

GET_PID_BY_PORT_SOCKSTAT_RESULTS = [
  "_tor     tor        4397  7  tcp4   51.64.7.84:9051    *:*",
  "_tor     tor        4397  12 tcp4   51.64.7.84:54011   80.3.121.7:9051",
  "_tor     tor        4397  15 tcp4   51.64.7.84:59374   7.42.1.102:9051"]

GET_PID_BY_PORT_LSOF_RESULTS = [
  "COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME",
  "tor     1745 atagar    6u  IPv4  14229      0t0  TCP 127.0.0.1:9051 (LISTEN)",
  "apache   329 atagar    6u  IPv4  14229      0t0  TCP 127.0.0.1:80 (LISTEN)"]

def mock_call(base_cmd, responses):
  """
  Provides mocking for the system module's call function. There are a couple
  ways of using this...
  
  - Simple usage is for base_cmd is the system call we want to respond to and
    responses is a list containing the respnose. For instance...
    
    mock_call("ls my_dir", ["file1", "file2", "file3"])
  
  - The base_cmd can be a formatted string and responses are a dictionary of
    completions for tat string to the responses. For instance...
    
    mock_call("ls %s", {"dir1": ["file1", "file2"], "dir2": ["file3", "file4"]})
  
  Arguments:
    base_cmd (str)         - command to match against
    responses (list, dict) - either list with the response, or mapping of
                             base_cmd formatted string completions to responses
  
  Returns:
    functor to override stem.util.system.call with
  """
  
  def _mock_call(base_cmd, responses, command):
    if isinstance(responses, list):
      if base_cmd == command: return responses
      else: return None
    else:
      for cmd_completion in responses:
        if command == base_cmd % cmd_completion:
          return responses[cmd_completion]
  
  return functools.partial(_mock_call, base_cmd, responses)

class TestSystem(unittest.TestCase):
  def setUp(self):
    mocking.mock(stem.util.proc.is_available, mocking.return_false())
    mocking.mock(system.is_available, mocking.return_true())
    mocking.mock(system.call, mocking.return_none())
  
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_is_running(self):
    """
    Exercises multiple use cases for the is_running function.
    """
    
    # mock response with a linux and bsd resolver
    running_commands = ["irssi", "moc", "tor", "ps", "  firefox  "]
    
    for ps_cmd in (system.IS_RUNNING_PS_LINUX, system.IS_RUNNING_PS_BSD):
      mocking.mock(system.call, mock_call(ps_cmd, running_commands))
      
      self.assertTrue(system.is_running("irssi"))
      self.assertTrue(system.is_running("moc"))
      self.assertTrue(system.is_running("tor"))
      self.assertTrue(system.is_running("ps"))
      self.assertTrue(system.is_running("firefox"))
      self.assertEqual(False, system.is_running("something_else"))
    
    # mock both calls failing
    mocking.mock(system.call, mocking.return_none())
    self.assertFalse(system.is_running("irssi"))
    self.assertEquals(None, system.is_running("irssi"))
  
  def test_get_pid_by_name_pgrep(self):
    """
    Tests the get_pid_by_name function with pgrep responses.
    """
    
    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses["success"] = ["1111"]
    responses["multiple_results"] = ["123", "456", "789"]
    mocking.mock(system.call, mock_call(system.GET_PID_BY_NAME_PGREP, responses))
    
    for test_input in responses:
      expected_response = 1111 if test_input == "success" else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))
  
  def test_get_pid_by_name_pidof(self):
    """
    Tests the get_pid_by_name function with pidof responses.
    """
    
    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses["success"] = ["1111"]
    responses["multiple_results"] = ["123 456 789"]
    mocking.mock(system.call, mock_call(system.GET_PID_BY_NAME_PIDOF, responses))
    
    for test_input in responses:
      expected_response = 1111 if test_input == "success" else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))
  
  def test_get_pid_by_name_ps_linux(self):
    """
    Tests the get_pid_by_name function with the linux variant of ps.
    """
    
    mocking.mock(system.is_bsd, mocking.return_false())
    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses["success"] = ["PID", " 1111"]
    responses["multiple_results"] = ["PID", " 123", " 456", " 789"]
    mocking.mock(system.call, mock_call(system.GET_PID_BY_NAME_PS_LINUX, responses))
    
    for test_input in responses:
      expected_response = 1111 if test_input == "success" else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))
  
  def test_get_pid_by_name_ps_bsd(self):
    """
    Tests the get_pid_by_name function with the bsd variant of ps.
    """
    
    mocking.mock(system.is_bsd, mocking.return_true())
    mocking.mock(system.call, mock_call(system.GET_PID_BY_NAME_PS_BSD, GET_PID_BY_NAME_PS_BSD))
    self.assertEquals(1, system.get_pid_by_name("launchd"))
    self.assertEquals(11, system.get_pid_by_name("DirectoryService"))
    self.assertEquals(None, system.get_pid_by_name("blarg"))
  
  def test_get_pid_by_name_lsof(self):
    """
    Tests the get_pid_by_name function with lsof responses.
    """
    
    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses["success"] = ["1111"]
    responses["multiple_results"] = ["123", "456", "789"]
    mocking.mock(system.call, mock_call(system.GET_PID_BY_NAME_LSOF, responses))
    
    for test_input in responses:
      expected_response = 1111 if test_input == "success" else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))
  
  def test_get_pid_by_port_netstat(self):
    """
    Tests the get_pid_by_port function with a netstat response.
    """
    
    mocking.mock(system.call, mock_call(system.GET_PID_BY_PORT_NETSTAT, GET_PID_BY_PORT_NETSTAT_RESULTS))
    self.assertEquals(1641, system.get_pid_by_port(9051))
    self.assertEquals(1641, system.get_pid_by_port("9051"))
    self.assertEquals(None, system.get_pid_by_port(631))
    self.assertEquals(None, system.get_pid_by_port(123))
  
  def test_get_pid_by_port_sockstat(self):
    """
    Tests the get_pid_by_port function with a sockstat response.
    """
    
    mocking.mock(system.call, mock_call(system.GET_PID_BY_PORT_SOCKSTAT % 9051, GET_PID_BY_PORT_SOCKSTAT_RESULTS))
    self.assertEquals(4397, system.get_pid_by_port(9051))
    self.assertEquals(4397, system.get_pid_by_port("9051"))
    self.assertEquals(None, system.get_pid_by_port(123))
  
  def test_get_pid_by_port_lsof(self):
    """
    Tests the get_pid_by_port function with a lsof response.
    """
    
    mocking.mock(system.call, mock_call(system.GET_PID_BY_PORT_LSOF, GET_PID_BY_PORT_LSOF_RESULTS))
    self.assertEquals(1745, system.get_pid_by_port(9051))
    self.assertEquals(1745, system.get_pid_by_port("9051"))
    self.assertEquals(329, system.get_pid_by_port(80))
    self.assertEquals(None, system.get_pid_by_port(123))
  
  def test_get_pid_by_open_file_lsof(self):
    """
    Tests the get_pid_by_open_file function with a lsof response.
    """
    
    lsof_query = system.GET_PID_BY_FILE_LSOF % "/tmp/foo"
    mocking.mock(system.call, mock_call(lsof_query, ["4762"]))
    self.assertEquals(4762, system.get_pid_by_open_file("/tmp/foo"))
    self.assertEquals(None, system.get_pid_by_open_file("/tmp/somewhere_else"))
  
  def test_get_cwd_pwdx(self):
    """
    Tests the get_cwd function with a pwdx response.
    """
    
    responses = {
      "3799": ["3799: /home/atagar"],
      "5839": ["5839: No such process"],
      "1234": ["malformed output"],
      "7878": None,
    }
    
    mocking.mock(system.call, mock_call(system.GET_CWD_PWDX, responses))
    
    for test_input in responses:
      expected_response = "/home/atagar" if test_input == "3799" else None
      self.assertEquals(expected_response, system.get_cwd(test_input))
  
  def test_get_cwd_lsof(self):
    """
    Tests the get_cwd function with a lsof response.
    """
    
    responses = {
      "75717": ["p75717", "n/Users/atagar/tor/src/or"],
      "1234": ["malformed output"],
      "7878": None,
    }
    
    mocking.mock(system.call, mock_call(system.GET_CWD_LSOF, responses))
    
    for test_input in responses:
      expected_response = "/Users/atagar/tor/src/or" if test_input == "75717" else None
      self.assertEquals(expected_response, system.get_cwd(test_input))
  
  def test_get_bsd_jail_id(self):
    """
    Tests the get_bsd_jail_id function.
    """
    
    responses = {
      "1111": ["JID", " 1"],
      "2222": ["JID", " 0"],
      "3333": ["JID", "bad data"],
      "4444": ["bad data"],
      "5555": [],
      "6666": None
    }
    
    mocking.mock(system.call, mock_call(system.GET_BSD_JAIL_ID_PS, responses))
    
    for test_input in responses:
      expected_response = 1 if test_input == "1111" else 0
      self.assertEquals(expected_response, system.get_bsd_jail_id(test_input))
  
  def test_expand_path_unix(self):
    """
    Tests the expand_path function. This does not exercise home directory
    expansions since that deals with our environment (that's left to integ
    tests).
    """
    
    mocking.mock(platform.system, mocking.return_value("Linux"))
    mocking.mock(os.path.join, posixpath.join, os.path)
    
    self.assertEquals("", system.expand_path(""))
    self.assertEquals("/tmp", system.expand_path("/tmp"))
    self.assertEquals("/tmp", system.expand_path("/tmp/"))
    self.assertEquals("/tmp", system.expand_path(".", "/tmp"))
    self.assertEquals("/tmp", system.expand_path("./", "/tmp"))
    self.assertEquals("/tmp/foo", system.expand_path("foo", "/tmp"))
    self.assertEquals("/tmp/foo", system.expand_path("./foo", "/tmp"))
    
  def test_expand_path_windows(self):
    """
    Tests the expand_path function on windows. This does not exercise
    home directory expansions since that deals with our environment
    (that's left to integ tests).
    """
    
    mocking.mock(platform.system, mocking.return_value("Windows"))
    mocking.mock(os.path.join, ntpath.join, os.path)
    
    self.assertEquals("", system.expand_path(""))
    self.assertEquals("C:\\tmp", system.expand_path("C:\\tmp"))
    self.assertEquals("C:\\tmp", system.expand_path("C:\\tmp\\"))
    self.assertEquals("C:\\tmp", system.expand_path(".", "C:\\tmp"))
    self.assertEquals("C:\\tmp", system.expand_path(".\\", "C:\\tmp"))
    self.assertEquals("C:\\tmp\\foo", system.expand_path("foo", "C:\\tmp"))
    self.assertEquals("C:\\tmp\\foo", system.expand_path(".\\foo", "C:\\tmp"))
