"""
Unit testing code for the stem.util.proc functions.
"""

import unittest

from stem.util import proc
from test import mocking

try:
  from StringIO import StringIO
except ImportError:
  from io import StringIO

try:
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch


class TestProc(unittest.TestCase):
  @patch('stem.util.proc._get_line')
  def test_system_start_time(self, get_line_mock):
    """
    Tests the system_start_time function.
    """

    get_line_mock.side_effect = lambda *params: {
      ('/proc/stat', 'btime', 'system start time'): 'btime 1001001',
    }[params]

    self.assertEqual(1001001, proc.system_start_time())

  @patch('stem.util.proc._get_line')
  def test_physical_memory(self, get_line_mock):
    """
    Tests the physical_memory function.
    """

    get_line_mock.side_effect = lambda *params: {
      ('/proc/meminfo', 'MemTotal:', 'system physical memory'): 'MemTotal:       12345 kB',
    }[params]

    self.assertEqual((12345 * 1024), proc.physical_memory())

  @patch('os.readlink')
  def test_cwd(self, readlink_mock):
    """
    Tests the cwd function with a given pid.
    """

    readlink_mock.side_effect = lambda param: {
      '/proc/24019/cwd': '/home/directory/TEST'
    }[param]

    self.assertEqual('/home/directory/TEST', proc.cwd(24019))

  @patch('stem.util.proc._get_line')
  def test_uid(self, get_line_mock):
    """
    Tests the uid function with a given pid.
    """

    for test_value in [(24019, 11111), (0, 22222)]:
      pid, uid = test_value

      get_line_mock.side_effect = lambda *params: {
        ('/proc/%s/status' % pid, 'Uid:', 'uid'): 'Uid: %s' % uid,
      }[params]

      self.assertEqual(uid, proc.uid(pid))

  @patch('stem.util.proc._get_lines')
  def test_memory_usage(self, get_lines_mock):
    """
    Tests the memory_usage function with a given pid.
    """

    get_lines_mock.side_effect = lambda *params: {
      ('/proc/1111/status', ('VmRSS:', 'VmSize:'), 'memory usage'):
        {'VmRSS:': 'VmRSS: 100 kB', 'VmSize:': 'VmSize: 1800 kB'}
    }[params]

    self.assertEqual((0, 0), proc.memory_usage(0))
    self.assertEqual((100 * 1024, 1800 * 1024), proc.memory_usage(1111))

  @patch('stem.util.proc._get_line')
  @patch('stem.util.proc.system_start_time', Mock(return_value = 10))
  def test_stats(self, get_line_mock):
    """
    Tests stats() with all combinations of stat_type arguments.
    """

    # list of all combinations of args with respective return values
    stat_combinations = mocking.get_all_combinations([
      ('command', 'test_program'),
      ('utime', '0.13'),
      ('stime', '0.14'),
      ('start time', '10.21'),
    ])

    stat_path = '/proc/24062/stat'
    stat = '1 (test_program) 2 3 4 5 6 7 8 9 10 11 12 13.0 14.0 15 16 17 18 19 20 21.0 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43'

    # tests the case where no stat_types are specified

    get_line_mock.side_effect = lambda *params: {
      (stat_path, '24062', 'process '): stat
    }[params]

    self.assertEqual((), proc.stats(24062))

    for stats in stat_combinations:
      # the stats variable is...
      #   [(arg1, resp1), (arg2, resp2)...]
      #
      # but we need...
      #   (arg1, arg2...), (resp1, resp2...).

      args, response = list(zip(*stats))

      get_line_mock.side_effect = lambda *params: {
        (stat_path, '24062', 'process %s' % ', '.join(args)): stat
      }[params]

      self.assertEqual(response, proc.stats(24062, *args))

      # tests the case where pid = 0

      if 'start time' in args:
        response = 10
      else:
        response = ()

        for arg in args:
          if arg == 'command':
            response += ('sched',)
          elif arg == 'utime':
            response += ('0',)
          elif arg == 'stime':
            response += ('0',)

      get_line_mock.side_effect = lambda *params: {
        ('/proc/0/stat', '0', 'process %s' % ', '.join(args)): stat
      }[params]

      self.assertEqual(response, proc.stats(0, *args))

  @patch('os.listdir')
  def test_file_descriptors_used(self, listdir_mock):
    """
    Tests the file_descriptors_used function.
    """

    # check that we reject bad pids

    for arg in (None, -100, 'hello',):
      self.assertRaises(IOError, proc.file_descriptors_used, arg)

    # when proc directory doesn't exist

    error_msg = "OSError: [Errno 2] No such file or directory: '/proc/2118/fd'"
    listdir_mock.side_effect = OSError(error_msg)

    try:
      proc.file_descriptors_used(2118)
      self.fail('We should raise when listdir() fails')
    except IOError as exc:
      expected = 'Unable to check number of file descriptors used: %s' % error_msg
      self.assertEqual(expected, str(exc))

    # successful calls

    listdir_mock.return_value = ['0', '1', '2', '3', '4', '5']
    listdir_mock.side_effect = None

    self.assertEqual(6, proc.file_descriptors_used(2118))
    self.assertEqual(6, proc.file_descriptors_used('2118'))

  @patch('os.listdir')
  @patch('os.readlink')
  @patch('stem.util.proc.open', create = True)
  def test_connections(self, open_mock, readlink_mock, listdir_mock):
    """
    Tests the connections function.
    """

    pid = 1111

    listdir_mock.side_effect = lambda param: {
      '/proc/%s/fd' % pid: ['1', '2', '3', '4'],
    }[param]

    readlink_mock.side_effect = lambda param: {
      '/proc/%s/fd/1' % pid: 'socket:[99999999]',
      '/proc/%s/fd/2' % pid: 'socket:[IIIIIIII]',
      '/proc/%s/fd/3' % pid: 'pipe:[30303]',
      '/proc/%s/fd/4' % pid: 'pipe:[40404]',
    }[param]

    tcp = '\n 0: 11111111:1111 22222222:2222 01 44444444:44444444 55:55555555 66666666 1111 8 99999999'
    udp = '\n A: BBBBBBBB:BBBB CCCCCCCC:CCCC DD EEEEEEEE:EEEEEEEE FF:FFFFFFFF GGGGGGGG 1111 H IIIIIIII'

    open_mock.side_effect = lambda param: {
      '/proc/net/tcp': StringIO(tcp),
      '/proc/net/udp': StringIO(udp)
    }[param]

    # tests the edge case of pid = 0
    self.assertEqual([], proc.connections(0))

    expected_results = [
      ('17.17.17.17', 4369, '34.34.34.34', 8738, 'tcp'),
      ('187.187.187.187', 48059, '204.204.204.204', 52428, 'udp'),
    ]

    self.assertEqual(expected_results, proc.connections(pid))
