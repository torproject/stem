"""
Unit tests for the stem.util.system functions. This works by mocking the
stem.util.system.call function to selectively exercise other functions. None of
these tests actually make system calls, use proc, or otherwise deal with the
system running the tests.
"""

import functools
import ntpath
import posixpath
import unittest

from stem.util import system

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

# Base responses for the get_pid_by_name tests. The 'success' and
# 'multiple_results' entries are filled in by tests.

GET_PID_BY_NAME_BASE_RESULTS = {
  'success': [],
  'multiple_results': [],
  'malformed_data': ['bad data'],
  'no_results': [],
  'command_fails': None,
}

# testing output for system calls

GET_PID_BY_NAME_PS_BSD = [
  '  PID   TT  STAT      TIME COMMAND',
  '    1   ??  Ss     9:00.22 launchd',
  '   10   ??  Ss     0:09.97 kextd',
  '   11   ??  Ss     5:47.36 DirectoryService',
  '   12   ??  Ss     3:01.44 notifyd']

GET_PID_BY_NAME_PS_BSD_MULTIPLE = [
  '  PID   TT  STAT      TIME COMMAND',
  '    1   ??  Ss     9:00.22 launchd',
  '   10   ??  Ss     0:09.97 kextd',
  '   41   ??  Ss     9:00.22 launchd']

GET_PID_BY_PORT_NETSTAT_RESULTS = [
  'Active Internet connections (only servers)',
  'Proto Recv-Q Send-Q Local Address           Foreign Address   State    PID/Program name',
  'tcp        0      0 127.0.0.1:631           0.0.0.0:*         LISTEN   -     ',
  'tcp        0      0 127.0.0.1:9051          0.0.0.0:*         LISTEN   1641/tor  ',
  'tcp6       0      0 ::1:631                 :::*              LISTEN   -     ',
  'udp        0      0 0.0.0.0:5353            0.0.0.0:*                  -     ',
  'udp6       0      0 fe80::7ae4:ff:fe2f::123 :::*                       -     ']

GET_PID_BY_PORT_SOCKSTAT_RESULTS = [
  '_tor     tor        4397  7  tcp4   51.64.7.84:9051    *:*',
  '_tor     tor        4397  12 tcp4   51.64.7.84:54011   80.3.121.7:9051',
  '_tor     tor        4397  15 tcp4   51.64.7.84:59374   7.42.1.102:9051']

GET_PID_BY_PORT_LSOF_RESULTS = [
  'COMMAND  PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME',
  'tor     1745 atagar    6u  IPv4  14229      0t0  TCP 127.0.0.1:9051 (LISTEN)',
  'apache   329 atagar    6u  IPv4  14229      0t0  TCP 127.0.0.1:80 (LISTEN)']

GET_BSD_JAIL_PATH_RESULTS = [
  '   JID  IP Address      Hostname      Path',
  '     1  10.0.0.2        tor-jail      /usr/jails/tor-jail',
]


def mock_call(base_cmd, responses):
  """
  Provides mocking for the system module's call function. There are a couple
  ways of using this...

  - Simple usage is for base_cmd is the system call we want to respond to and
    responses is a list containing the respnose. For instance...

    mock_call('ls my_dir', ['file1', 'file2', 'file3'])

  - The base_cmd can be a formatted string and responses are a dictionary of
    completions for tat string to the responses. For instance...

    mock_call('ls %s', {'dir1': ['file1', 'file2'], 'dir2': ['file3', 'file4']})

  :param str base_cmd: command to match against
  :param list,dict responses: either list with the response, or mapping of
    base_cmd formatted string completions to responses

  :returns: **functor** to override stem.util.system.call with
  """

  def _mock_call(base_cmd, responses, command, default = None):
    if isinstance(responses, list):
      if base_cmd == command:
        return responses
      else:
        return default
    else:
      for cmd_completion in responses:
        if command == base_cmd % cmd_completion:
          return responses[cmd_completion]

      return default

  return functools.partial(_mock_call, base_cmd, responses)


class TestSystem(unittest.TestCase):
  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_is_running(self, call_mock):
    """
    Exercises multiple use cases for the is_running function.
    """

    # mock response with a linux and bsd resolver
    running_commands = [u'irssi', u'moc', u'tor', u'ps', u'  firefox  ']

    for ps_cmd in (system.IS_RUNNING_PS_LINUX, system.IS_RUNNING_PS_BSD):
      call_mock.side_effect = mock_call(ps_cmd, running_commands)

      self.assertTrue(system.is_running('irssi'))
      self.assertTrue(system.is_running('moc'))
      self.assertTrue(system.is_running('tor'))
      self.assertTrue(system.is_running('ps'))
      self.assertTrue(system.is_running('firefox'))
      self.assertEqual(False, system.is_running('something_else'))

    # mock both calls failing

    call_mock.return_value = None
    call_mock.side_effect = None
    self.assertFalse(system.is_running('irssi'))
    self.assertEquals(None, system.is_running('irssi'))

  @patch('stem.util.system.call')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_name_by_pid_ps(self, call_mock):
    """
    Tests the get_name_by_pid function with ps responses.
    """

    responses = {
      'success': ['COMMAND', 'vim'],
      'malformed_command_1': ['COMMAND'],
      'malformed_command_2': ['foobar'],
      'malformed_command_3': ['NOT_COMMAND', 'vim'],
      'no_results': [],
      'command_fails': None,
    }

    call_mock.side_effect = mock_call(system.GET_NAME_BY_PID_PS, responses)

    for test_input in responses:
      expected_response = 'vim' if test_input == 'success' else None
      self.assertEquals(expected_response, system.get_name_by_pid(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_name_pgrep(self, call_mock):
    """
    Tests the get_pid_by_name function with pgrep responses.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['1111']
    responses['multiple_results'] = ['123', '456', '789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PGREP, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))

    self.assertEquals([123, 456, 789], system.get_pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_name_pidof(self, call_mock):
    """
    Tests the get_pid_by_name function with pidof responses.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['1111']
    responses['multiple_results'] = ['123 456 789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PIDOF, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))

    self.assertEquals([123, 456, 789], system.get_pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_bsd', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_name_ps_linux(self, call_mock):
    """
    Tests the get_pid_by_name function with the linux variant of ps.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['PID', ' 1111']
    responses['multiple_results'] = ['PID', ' 123', ' 456', ' 789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PS_LINUX, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))

    self.assertEquals([123, 456, 789], system.get_pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_bsd', Mock(return_value = True))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_name_ps_bsd(self, call_mock):
    """
    Tests the get_pid_by_name function with the bsd variant of ps.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PS_BSD, GET_PID_BY_NAME_PS_BSD)
    self.assertEquals(1, system.get_pid_by_name('launchd'))
    self.assertEquals(11, system.get_pid_by_name('DirectoryService'))
    self.assertEquals(None, system.get_pid_by_name('blarg'))

    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PS_BSD, GET_PID_BY_NAME_PS_BSD_MULTIPLE)

    self.assertEquals([1, 41], system.get_pid_by_name('launchd', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_name_lsof(self, call_mock):
    """
    Tests the get_pid_by_name function with lsof responses.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['1111']
    responses['multiple_results'] = ['123', '456', '789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_LSOF, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEquals(expected_response, system.get_pid_by_name(test_input))

    self.assertEquals([123, 456, 789], system.get_pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_port_netstat(self, call_mock):
    """
    Tests the get_pid_by_port function with a netstat response.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_PORT_NETSTAT, GET_PID_BY_PORT_NETSTAT_RESULTS)
    self.assertEquals(1641, system.get_pid_by_port(9051))
    self.assertEquals(1641, system.get_pid_by_port('9051'))
    self.assertEquals(None, system.get_pid_by_port(631))
    self.assertEquals(None, system.get_pid_by_port(123))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_port_sockstat(self, call_mock):
    """
    Tests the get_pid_by_port function with a sockstat response.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_PORT_SOCKSTAT % 9051, GET_PID_BY_PORT_SOCKSTAT_RESULTS)
    self.assertEquals(4397, system.get_pid_by_port(9051))
    self.assertEquals(4397, system.get_pid_by_port('9051'))
    self.assertEquals(None, system.get_pid_by_port(123))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_port_lsof(self, call_mock):
    """
    Tests the get_pid_by_port function with a lsof response.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_PORT_LSOF, GET_PID_BY_PORT_LSOF_RESULTS)
    self.assertEquals(1745, system.get_pid_by_port(9051))
    self.assertEquals(1745, system.get_pid_by_port('9051'))
    self.assertEquals(329, system.get_pid_by_port(80))
    self.assertEquals(None, system.get_pid_by_port(123))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_pid_by_open_file_lsof(self, call_mock):
    """
    Tests the get_pid_by_open_file function with a lsof response.
    """

    lsof_query = system.GET_PID_BY_FILE_LSOF % '/tmp/foo'
    call_mock.side_effect = mock_call(lsof_query, ['4762'])
    self.assertEquals(4762, system.get_pid_by_open_file('/tmp/foo'))

    call_mock.return_value = []
    call_mock.side_effect = None
    self.assertEquals(None, system.get_pid_by_open_file('/tmp/somewhere_else'))

  @patch('stem.util.system.call')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_cwd_pwdx(self, call_mock):
    """
    Tests the get_cwd function with a pwdx response.
    """

    responses = {
      '3799': ['3799: /home/atagar'],
      '5839': ['5839: No such process'],
      '1234': ['malformed output'],
      '7878': None,
    }

    call_mock.side_effect = mock_call(system.GET_CWD_PWDX, responses)

    for test_input in responses:
      expected_response = '/home/atagar' if test_input == '3799' else None
      self.assertEquals(expected_response, system.get_cwd(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_cwd_lsof(self, call_mock):
    """
    Tests the get_cwd function with a lsof response.
    """

    responses = {
      '75717': ['p75717', 'n/Users/atagar/tor/src/or'],
      '1234': ['malformed output'],
      '7878': [],
    }

    call_mock.side_effect = mock_call(system.GET_CWD_LSOF, responses)

    for test_input in responses:
      expected_response = '/Users/atagar/tor/src/or' if test_input == '75717' else None
      self.assertEquals(expected_response, system.get_cwd(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_bsd_jail_id(self, call_mock):
    """
    Tests the get_bsd_jail_id function.
    """

    responses = {
      '1111': ['JID', ' 1'],
      '2222': ['JID', ' 0'],
      '3333': ['JID', 'bad data'],
      '4444': ['bad data'],
      '5555': [],
      '6666': []
    }

    call_mock.side_effect = mock_call(system.GET_BSD_JAIL_ID_PS, responses)

    for test_input in responses:
      expected_response = 1 if test_input == '1111' else 0
      self.assertEquals(expected_response, system.get_bsd_jail_id(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_get_bsd_jail_path(self, call_mock):
    """
    Tests the get_bsd_jail_path function.
    """

    # check when we don't have a jail

    call_mock.return_value = []
    self.assertEquals(None, system.get_bsd_jail_path(1))

    call_mock.side_effect = mock_call(system.GET_BSD_JAIL_PATH % '1', GET_BSD_JAIL_PATH_RESULTS)
    self.assertEquals('/usr/jails/tor-jail', system.get_bsd_jail_path(1))

  @patch('platform.system', Mock(return_value = 'Linux'))
  @patch('os.path.join', Mock(side_effect = posixpath.join))
  def test_expand_path_unix(self):
    """
    Tests the expand_path function. This does not exercise home directory
    expansions since that deals with our environment (that's left to integ
    tests).
    """

    self.assertEquals('', system.expand_path(''))
    self.assertEquals('/tmp', system.expand_path('/tmp'))
    self.assertEquals('/tmp', system.expand_path('/tmp/'))
    self.assertEquals('/tmp', system.expand_path('.', '/tmp'))
    self.assertEquals('/tmp', system.expand_path('./', '/tmp'))
    self.assertEquals('/tmp/foo', system.expand_path('foo', '/tmp'))
    self.assertEquals('/tmp/foo', system.expand_path('./foo', '/tmp'))

  @patch('platform.system', Mock(return_value = 'Windows'))
  @patch('os.path.join', Mock(side_effect = ntpath.join))
  def test_expand_path_windows(self):
    """
    Tests the expand_path function on windows. This does not exercise
    home directory expansions since that deals with our environment
    (that's left to integ tests).
    """

    self.assertEquals('', system.expand_path(''))
    self.assertEquals('C:\\tmp', system.expand_path('C:\\tmp'))
    self.assertEquals('C:\\tmp', system.expand_path('C:\\tmp\\'))
    self.assertEquals('C:\\tmp', system.expand_path('.', 'C:\\tmp'))
    self.assertEquals('C:\\tmp', system.expand_path('.\\', 'C:\\tmp'))
    self.assertEquals('C:\\tmp\\foo', system.expand_path('foo', 'C:\\tmp'))
    self.assertEquals('C:\\tmp\\foo', system.expand_path('.\\foo', 'C:\\tmp'))
