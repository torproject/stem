"""
Unit testing code for the stem.util.proc functions.
"""

import os
import StringIO
import unittest

from stem.util import proc
from test import mocking

class TestProc(unittest.TestCase):
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_get_system_start_time(self):
    """
    Tests the get_system_start_time function.
    """
    
    mocking.mock(proc._get_line, mocking.return_for_args({
      ('/proc/stat', 'btime', 'system start time'): 'btime 1001001',
    }))
    
    self.assertEquals(1001001, proc.get_system_start_time())
  
  def test_get_physical_memory(self):
    """
    Tests the get_physical_memory function.
    """
    
    mocking.mock(proc._get_line, mocking.return_for_args({
      ('/proc/meminfo', 'MemTotal:', 'system physical memory'): 'MemTotal:       12345 kB',
    }))
    
    self.assertEquals((12345 * 1024), proc.get_physical_memory())
  
  def test_get_cwd(self):
    """
    Tests the get_cwd function with a given pid.
    """
    
    mocking.mock(os.readlink, mocking.return_for_args({
      ('/proc/24019/cwd',): '/home/directory/TEST'
    }), os)
    
    self.assertEquals('/home/directory/TEST', proc.get_cwd(24019))
  
  def test_get_uid(self):
    """
    Tests the get_uid function with a given pid.
    """
    
    for test_value in [(24019, 11111), (0, 22222)]:
      pid, uid = test_value
      mocking.mock(proc._get_line, mocking.return_for_args({
        ("/proc/%s/status" % pid, 'Uid:', 'uid'): 'Uid: %s' % uid
      }))
      
      self.assertEquals(uid, proc.get_uid(pid))
  
  def test_get_memory_usage(self):
    """
    Tests the get_memory_usage function with a given pid.
    """
    
    mocking.mock(proc._get_lines, mocking.return_for_args({
      ('/proc/1111/status', ('VmRSS:', 'VmSize:'), 'memory usage'):
        {'VmRSS:': 'VmRSS: 100 kB', 'VmSize:': 'VmSize: 1800 kB'}
    }))
    
    self.assertEqual((0, 0), proc.get_memory_usage(0))
    self.assertEqual((100 * 1024, 1800 * 1024), proc.get_memory_usage(1111))
  
  def test_get_stats(self):
    """
    Tests get_stats() with all combinations of stat_type arguments.
    """
    
    # list of all combinations of args with respective return values
    stat_combinations = mocking.get_all_combinations([
      ('command', 'test_program'),
      ('utime', '0.13'),
      ('stime', '0.14'),
      ('start time', '10.21'),
    ])
    
    stat_path = "/proc/24062/stat"
    stat = '1 (test_program) 2 3 4 5 6 7 8 9 10 11 12 13.0 14.0 15 16 17 18 19 20 21.0 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43'
    
    mocking.mock(proc.get_system_start_time, mocking.return_value(10))
    
    # tests the case where no stat_types are specified
    mocking.mock(proc._get_line, mocking.return_for_args({
      (stat_path, '24062', 'process '): stat
    }))
    
    self.assertEquals((), proc.get_stats(24062))
    
    for stats in stat_combinations:
      # the stats variable is...
      #   [(arg1, resp1), (arg2, resp2)...]
      #
      # but we need...
      #   (arg1, arg2...), (resp1, resp2...).
      
      args, response = zip(*stats)
      
      mocking.mock(proc._get_line, mocking.return_for_args({
        (stat_path, '24062', 'process %s' % ', '.join(args)): stat
      }))
      
      self.assertEquals(response, proc.get_stats(24062, *args))
      
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
      
      mocking.mock(proc._get_line, mocking.return_for_args({
        ('/proc/0/stat', '0', 'process %s' % ', '.join(args)): stat
      }))
      
      self.assertEquals(response, proc.get_stats(0, *args))
  
  def test_get_connections(self):
    """
    Tests the get_connections function.
    """
    
    pid = 1111
    
    mocking.mock(os.listdir, mocking.return_for_args({
      ('/proc/%s/fd' % pid,): ['1', '2', '3', '4'],
    }), os)
    
    mocking.mock(os.readlink, mocking.return_for_args({
      ('/proc/%s/fd/1' % pid,): 'socket:[99999999]',
      ('/proc/%s/fd/2' % pid,): 'socket:[IIIIIIII]',
      ('/proc/%s/fd/3' % pid,): 'pipe:[30303]',
      ('/proc/%s/fd/4' % pid,): 'pipe:[40404]',
    }), os)
    
    tcp = '\n 0: 11111111:1111 22222222:2222 01 44444444:44444444 55:55555555 66666666 1111 8 99999999'
    udp = '\n A: BBBBBBBB:BBBB CCCCCCCC:CCCC DD EEEEEEEE:EEEEEEEE FF:FFFFFFFF GGGGGGGG 1111 H IIIIIIII'
    
    mocking.mock(open, mocking.return_for_args({
      ('/proc/net/tcp',): StringIO.StringIO(tcp),
      ('/proc/net/udp',): StringIO.StringIO(udp)
    }))
    
    # tests the edge case of pid = 0
    self.assertEquals([], proc.get_connections(0))
    
    expected_results = [
      ('17.17.17.17', 4369, '34.34.34.34', 8738),
      ('187.187.187.187', 48059, '204.204.204.204', 52428),
    ]
    
    self.assertEquals(expected_results, proc.get_connections(pid))

