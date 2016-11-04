"""
Unit tests for the stem.util.system functions. This works by mocking the
stem.util.system.call function to selectively exercise other functions. None of
these tests actually make system calls, use proc, or otherwise deal with the
system running the tests.
"""

import functools
import ntpath
import os
import posixpath
import tempfile
import unittest

from stem.util import str_type, system

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

# Base responses for the pid_by_name tests. The 'success' and
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


GET_PID_BY_NAME_TASKLIST_RESULTS = [
  'Image Name                     PID Session Name        Session#    Mem Usage',
  'System Idle Process              0 Services                   0         20 K',
  'svchost.exe                    872 Services                   0      8,744 K',
  'hpservice.exe                 1112 Services                   0      3,828 K',
  'tor.exe                       3712 Console                    1     29,976 K',
  'tor.exe                       3713 Console                    1     21,976 K',
  'conhost.exe                   3012 Console                    1      4,652 K']

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
    running_commands = [str_type('irssi'), str_type('moc'), str_type('tor'),
                        str_type('ps'), str_type('  firefox  ')]

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
    self.assertEqual(None, system.is_running('irssi'))

  @patch('stem.util.system.call')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_name_by_pid_ps(self, call_mock):
    """
    Tests the name_by_pid function with ps responses.
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
      self.assertEqual(expected_response, system.name_by_pid(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  @patch('stem.util.system.is_windows', Mock(return_value = False))
  def test_pid_by_name_pgrep(self, call_mock):
    """
    Tests the pid_by_name function with pgrep responses.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['1111']
    responses['multiple_results'] = ['123', '456', '789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PGREP, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEqual(expected_response, system.pid_by_name(test_input))

    self.assertEqual([123, 456, 789], system.pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  @patch('stem.util.system.is_windows', Mock(return_value = False))
  def test_pid_by_name_pidof(self, call_mock):
    """
    Tests the pid_by_name function with pidof responses.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['1111']
    responses['multiple_results'] = ['123 456 789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PIDOF, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEqual(expected_response, system.pid_by_name(test_input))

    self.assertEqual([123, 456, 789], system.pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_bsd', Mock(return_value = False))
  @patch('stem.util.system.is_windows', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_pid_by_name_ps_linux(self, call_mock):
    """
    Tests the pid_by_name function with the linux variant of ps.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['PID', ' 1111']
    responses['multiple_results'] = ['PID', ' 123', ' 456', ' 789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PS_LINUX, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEqual(expected_response, system.pid_by_name(test_input))

    self.assertEqual([123, 456, 789], system.pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_bsd', Mock(return_value = True))
  @patch('stem.util.system.is_windows', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_pid_by_name_ps_bsd(self, call_mock):
    """
    Tests the pid_by_name function with the bsd variant of ps.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PS_BSD, GET_PID_BY_NAME_PS_BSD)
    self.assertEqual(1, system.pid_by_name('launchd'))
    self.assertEqual(11, system.pid_by_name('DirectoryService'))
    self.assertEqual(None, system.pid_by_name('blarg'))

    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_PS_BSD, GET_PID_BY_NAME_PS_BSD_MULTIPLE)

    self.assertEqual([1, 41], system.pid_by_name('launchd', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  @patch('stem.util.system.is_windows', Mock(return_value = False))
  def test_pid_by_name_lsof(self, call_mock):
    """
    Tests the pid_by_name function with lsof responses.
    """

    responses = dict(GET_PID_BY_NAME_BASE_RESULTS)
    responses['success'] = ['1111']
    responses['multiple_results'] = ['123', '456', '789']
    call_mock.side_effect = mock_call(system.GET_PID_BY_NAME_LSOF, responses)

    for test_input in responses:
      expected_response = 1111 if test_input == 'success' else None
      self.assertEqual(expected_response, system.pid_by_name(test_input))

    self.assertEqual([123, 456, 789], system.pid_by_name('multiple_results', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  @patch('stem.util.system.is_windows', Mock(return_value = True))
  def test_pid_by_name_tasklist(self, call_mock):
    """
    Tests the pid_by_name function with tasklist responses.
    """

    call_mock.side_effect = mock_call('tasklist', GET_PID_BY_NAME_TASKLIST_RESULTS)
    self.assertEqual(3712, system.pid_by_name('tor'))
    self.assertEqual(None, system.pid_by_name('DirectoryService'))
    self.assertEqual(None, system.pid_by_name('blarg'))
    self.assertEqual([3712, 3713], system.pid_by_name('tor', multiple = True))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_pid_by_port_netstat(self, call_mock):
    """
    Tests the pid_by_port function with a netstat response.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_PORT_NETSTAT, GET_PID_BY_PORT_NETSTAT_RESULTS)
    self.assertEqual(1641, system.pid_by_port(9051))
    self.assertEqual(1641, system.pid_by_port('9051'))
    self.assertEqual(None, system.pid_by_port(631))
    self.assertEqual(None, system.pid_by_port(123))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_pid_by_port_sockstat(self, call_mock):
    """
    Tests the pid_by_port function with a sockstat response.
    """
    call_mock.side_effect = mock_call(system.GET_PID_BY_PORT_SOCKSTAT % 9051, GET_PID_BY_PORT_SOCKSTAT_RESULTS)
    self.assertEqual(4397, system.pid_by_port(9051))
    self.assertEqual(4397, system.pid_by_port('9051'))
    self.assertEqual(None, system.pid_by_port(123))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_pid_by_port_lsof(self, call_mock):
    """
    Tests the pid_by_port function with a lsof response.
    """

    call_mock.side_effect = mock_call(system.GET_PID_BY_PORT_LSOF, GET_PID_BY_PORT_LSOF_RESULTS)
    self.assertEqual(1745, system.pid_by_port(9051))
    self.assertEqual(1745, system.pid_by_port('9051'))
    self.assertEqual(329, system.pid_by_port(80))
    self.assertEqual(None, system.pid_by_port(123))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_pid_by_open_file_lsof(self, call_mock):
    """
    Tests the pid_by_open_file function with a lsof response.
    """

    lsof_query = system.GET_PID_BY_FILE_LSOF % '/tmp/foo'
    call_mock.side_effect = mock_call(lsof_query, ['4762'])
    self.assertEqual(4762, system.pid_by_open_file('/tmp/foo'))

    call_mock.return_value = []
    call_mock.side_effect = None
    self.assertEqual(None, system.pid_by_open_file('/tmp/somewhere_else'))

  @patch('stem.util.system.call')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_cwd_pwdx(self, call_mock):
    """
    Tests the cwd function with a pwdx response.
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
      self.assertEqual(expected_response, system.cwd(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.proc.is_available', Mock(return_value = False))
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_cwd_lsof(self, call_mock):
    """
    Tests the cwd function with a lsof response.
    """

    responses = {
      '75717': ['p75717', 'n/Users/atagar/tor/src/or'],
      '75718': ['p75718', 'fcwd', 'n/Users/atagar/tor/src/or'],
      '1234': ['malformed output'],
      '7878': [],
    }

    call_mock.side_effect = mock_call(system.GET_CWD_LSOF, responses)

    for test_input in responses:
      expected_response = '/Users/atagar/tor/src/or' if test_input in ('75717', '75718') else None
      self.assertEqual(expected_response, system.cwd(test_input))

  def test_tail(self):
    """
    Exercise our tail() function with a variety of inputs.
    """

    path = os.path.join(os.path.dirname(__file__), 'text_file')

    # by file handle

    with open(path, 'rb') as riddle_file:
      self.assertEqual(['  both the wicked and sweet.'], list(system.tail(riddle_file, 1)))

    self.assertEqual([], list(system.tail(path, 0)))
    self.assertEqual(['  both the wicked and sweet.'], list(system.tail(path, 1)))
    self.assertEqual(['  both the wicked and sweet.', "but I'm with people you meet"], list(system.tail(path, 2)))

    self.assertEqual(14, len(list(system.tail(path))))
    self.assertEqual(14, len(list(system.tail(path, 200))))

    self.assertRaises(IOError, list, system.tail('/path/doesnt/exist'))

    fd, temp_path = tempfile.mkstemp()
    os.chmod(temp_path, 0o077)  # remove read permissions
    self.assertRaises(IOError, list, system.tail(temp_path))
    os.close(fd)
    os.remove(temp_path)

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_bsd_jail_id(self, call_mock):
    """
    Tests the bsd_jail_id function.
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
      self.assertEqual(expected_response, system.bsd_jail_id(test_input))

  @patch('stem.util.system.call')
  @patch('stem.util.system.is_available', Mock(return_value = True))
  def test_bsd_jail_path(self, call_mock):
    """
    Tests the bsd_jail_path function.
    """

    # check when we don't have a jail

    call_mock.return_value = []
    self.assertEqual(None, system.bsd_jail_path(1))

    call_mock.side_effect = mock_call(system.GET_BSD_JAIL_PATH % '1', GET_BSD_JAIL_PATH_RESULTS)
    self.assertEqual('/usr/jails/tor-jail', system.bsd_jail_path(1))

  @patch('platform.system', Mock(return_value = 'Linux'))
  @patch('os.path.join', Mock(side_effect = posixpath.join))
  def test_expand_path_unix(self):
    """
    Tests the expand_path function. This does not exercise home directory
    expansions since that deals with our environment (that's left to integ
    tests).
    """

    self.assertEqual('', system.expand_path(''))
    self.assertEqual('/tmp', system.expand_path('/tmp'))
    self.assertEqual('/tmp', system.expand_path('/tmp/'))
    self.assertEqual('/tmp', system.expand_path('.', '/tmp'))
    self.assertEqual('/tmp', system.expand_path('./', '/tmp'))
    self.assertEqual('/tmp/foo', system.expand_path('foo', '/tmp'))
    self.assertEqual('/tmp/foo', system.expand_path('./foo', '/tmp'))

  @patch('platform.system', Mock(return_value = 'Windows'))
  @patch('os.path.join', Mock(side_effect = ntpath.join))
  def test_expand_path_windows(self):
    """
    Tests the expand_path function on windows. This does not exercise
    home directory expansions since that deals with our environment
    (that's left to integ tests).
    """

    self.assertEqual('', system.expand_path(''))
    self.assertEqual('C:\\tmp', system.expand_path('C:\\tmp'))
    self.assertEqual('C:\\tmp', system.expand_path('C:\\tmp\\'))
    self.assertEqual('C:\\tmp', system.expand_path('.', 'C:\\tmp'))
    self.assertEqual('C:\\tmp', system.expand_path('.\\', 'C:\\tmp'))
    self.assertEqual('C:\\tmp\\foo', system.expand_path('foo', 'C:\\tmp'))
    self.assertEqual('C:\\tmp\\foo', system.expand_path('.\\foo', 'C:\\tmp'))
