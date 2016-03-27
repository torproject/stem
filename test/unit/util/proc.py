"""
Unit testing code for the stem.util.proc functions.
"""

import io
import unittest

from stem.util import proc
from stem.util.connection import Connection
from test import mocking

try:
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

TCP6_CONTENT = b"""\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1495 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   106        0 14347030 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000000000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1457 1 0000000000000000 100 0 0 10 0
   2: 00000000000000000000000000000000:0217 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 6606 1 0000000000000000 100 0 0 10 0
   3: F804012A4A5190010000000002000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4372 1 0000000000000000 100 0 0 10 0
   4: 00000000000000000000000000000000:14A1 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   106        0 14347031 1 0000000000000000 100 0 0 10 0
   5: 00000000000000000000000000000000:1466 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000   106        0 14347029 1 0000000000000000 100 0 0 10 0
   6: F804012A4A5190010000000002000000:01BB 38060120404100A0000000008901FFFF:9DF3 01 00000000:00000000 00:00000000 00000000   101        0 42088802 1 0000000000000000 20 4 25 10 7
   7: F804012A4A5190010000000002000000:01BB 58080120020002000000BBAA26153B56:ADB5 01 00000000:00000000 00:00000000 00000000   101        0 41691357 1 0000000000000000 24 4 32 10 7
   8: 0000000000000000FFFF00004B9E0905:1466 0000000000000000FFFF00002186364E:95BA 01 00000000:00000000 02:000A5B3D 00000000   106        0 41878761 2 0000000000000000 26 4 30 10 -1
   9: F804012A4A5190010000000002000000:1495 F806012011006F120000000026000000:C5A2 01 00000000:00000000 02:000A5B3D 00000000   106        0 41825895 2 0000000000000000 21 4 15 10 -1
  10: 0000000000000000FFFF00004B9E0905:1466 0000000000000000FFFF00002186364E:951E 01 00000000:00000000 02:00090E70 00000000   106        0 41512577 2 0000000000000000 26 4 31 10 -1
"""


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
  @patch('os.path.exists')
  @patch('os.readlink')
  @patch('stem.util.proc.open', create = True)
  def test_connections(self, open_mock, readlink_mock, path_exists_mock, listdir_mock):
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

    tcp = b'\n 0: 11111111:1111 22222222:2222 01 44444444:44444444 55:55555555 66666666 1111 8 99999999'
    udp = b'\n A: BBBBBBBB:BBBB CCCCCCCC:CCCC DD EEEEEEEE:EEEEEEEE FF:FFFFFFFF GGGGGGGG 1111 H IIIIIIII'

    path_exists_mock.side_effect = lambda param: {
      '/proc/net/tcp': True,
      '/proc/net/tcp6': False,
      '/proc/net/udp': True,
      '/proc/net/udp6': False
    }[param]

    open_mock.side_effect = lambda param, mode: {
      '/proc/net/tcp': io.BytesIO(tcp),
      '/proc/net/udp': io.BytesIO(udp)
    }[param]

    expected_results = [
      Connection('17.17.17.17', 4369, '34.34.34.34', 8738, 'tcp', False),
      Connection('187.187.187.187', 48059, '204.204.204.204', 52428, 'udp', False),
    ]

    self.assertEqual(expected_results, proc.connections(pid))

  @patch('os.listdir')
  @patch('os.path.exists')
  @patch('os.readlink')
  @patch('stem.util.proc.open', create = True)
  def test_connections_ipv6(self, open_mock, readlink_mock, path_exists_mock, listdir_mock):
    """
    Tests the connections function with ipv6 addresses.
    """

    pid = 1111

    listdir_mock.side_effect = lambda param: {
      '/proc/%s/fd' % pid: ['1', '2'],
    }[param]

    readlink_mock.side_effect = lambda param: {
      '/proc/%s/fd/1' % pid: 'socket:[42088802]',
      '/proc/%s/fd/2' % pid: 'socket:[41691357]',
    }[param]

    path_exists_mock.side_effect = lambda param: {
      '/proc/net/tcp6': True,
      '/proc/net/udp6': False
    }[param]

    open_mock.side_effect = lambda param, mode: {
      '/proc/net/tcp': io.BytesIO(b''),
      '/proc/net/tcp6': io.BytesIO(TCP6_CONTENT),
      '/proc/net/udp': io.BytesIO(b''),
    }[param]

    expected_results = [
      Connection('2a01:04f8:0190:514a:0000:0000:0000:0002', 443, '2001:0638:a000:4140:0000:0000:ffff:0189', 40435, 'tcp', True),
      Connection('2a01:04f8:0190:514a:0000:0000:0000:0002', 443, '2001:0858:0002:0002:aabb:0000:563b:1526', 44469, 'tcp', True),
    ]

    self.assertEqual(expected_results, proc.connections(pid = pid))

  @patch('os.path.exists')
  @patch('pwd.getpwnam')
  @patch('stem.util.proc.open', create = True)
  def test_connections_ipv6_by_user(self, open_mock, getpwnam_mock, path_exists_mock):
    """
    Tests the connections function with ipv6 addresses.
    """

    getpwnam_mock('me').pw_uid = 106

    path_exists_mock.side_effect = lambda param: {
      '/proc/net/tcp6': True,
      '/proc/net/udp6': False
    }[param]

    open_mock.side_effect = lambda param, mode: {
      '/proc/net/tcp': io.BytesIO(b''),
      '/proc/net/tcp6': io.BytesIO(TCP6_CONTENT),
      '/proc/net/udp': io.BytesIO(b''),
    }[param]

    expected_results = [
      Connection('0000:0000:0000:0000:0000:ffff:0509:9e4b', 5222, '0000:0000:0000:0000:0000:ffff:4e36:8621', 38330, 'tcp', True),
      Connection('2a01:04f8:0190:514a:0000:0000:0000:0002', 5269, '2001:06f8:126f:0011:0000:0000:0000:0026', 50594, 'tcp', True),
      Connection('0000:0000:0000:0000:0000:ffff:0509:9e4b', 5222, '0000:0000:0000:0000:0000:ffff:4e36:8621', 38174, 'tcp', True),
    ]

    self.assertEqual(expected_results, proc.connections(user = 'me'))
