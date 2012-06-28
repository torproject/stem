"""
Unit testing code for the stem.util.proc functions.

"""
import os
import time
import unittest
import operator
import functools
import itertools
import cStringIO

import test.mocking as mocking
import stem.util.proc as proc

class TargetError(Exception):
  """
  Raised when a function that needs to be mocked cannot be called.
  
  This occurs when the caller's arguments don't match the expected arguments
  and no target is given.
  """
  def __init__(self, value):
    self.value = value
  def __str__(self):
    return repr(self.value)

def mock_fn(arguments_returns, target=None):
  """
  Provides a lambda function that may be used to mock another function.
  
  This function operates under the precondition that len(exp_args) = len(return_vals)
  
  :param dict args_rets: expected input value(s) as tuples are the key and return values are the values of the dictionary.
  :param function target: target function to be called if mocking doesn't cover this input
  
  :returns: function _mocker such that...
  *return_vals[i]     a = exp_args[i]
  *target(*a)         a != exp_args[i] and target != None
  *raise TargetError  a != exp_args[i] and target = None
  """
  
  def _mocked(args_rets, tgt, *arg):
    try:
     # First check if given input matches one of the inputs to be mocked.
     return args_rets[arg]
    except KeyError:
      if tgt:
        return tgt(*arg)
      else:
        raise TargetError("A relevant function could not be applied")
  return functools.partial(_mocked, arguments_returns, target)

def find_subsets(xs):
  """
  Used with the builtin zip function to create all possible combinations
  of the elements of two lists.
  
  Called in test_get_stats().
  
  :param xs: list of tuples given by calling zip on two lists
  
  :returns: a list of lists of tuples containing all possible combinations of arguments. Will be of the form [[(arg1, resp1),(arg2, resp2),...], [(arg1, resp1),(arg3, resp3),...],...]
  """
  
  #  Base case is the empty list.
  if len(xs) == 0:
    return [[]]
  else:
    subs = find_subsets(xs[1:])
    subs_w_x0 = []
    for s in subs:
      subs_w_x0 = subs_w_x0 + [s + [xs[0]]]
    return subs + subs_w_x0

class TestProc(unittest.TestCase):
  
  def setUp(self):
    mocking.mock(time.time, mocking.return_value(3.14159))
  
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_get_system_start_time(self):
    """
    Tests the get_system_start_time function.
    """
    
    mocking.mock(proc._get_line, mock_fn({('/proc/stat', 'btime', 'system start time'):'btime 1001001'}))
    
    # Single test as get_system_start_time takes no arguments
    self.assertEquals(1001001, proc.get_system_start_time())
  
  def test_get_physical_memory(self):
    """
    Tests the get_physical_memory function.
    """
    
    mocking.mock(proc._get_line, mock_fn({('/proc/meminfo', 'MemTotal:', 'system physical memory'):'MemTotal:       12345 kB'}))
    
    self.assertEquals((12345*1024), proc.get_physical_memory())
    
  def test_get_cwd(self):
    """
    Tests the get_cwd function with a given pid.
    """
    
    mocking.mock(os.readlink, mock_fn({('/proc/24019/cwd',):'/home/directory/TEST'}, os.listdir), os)
    
    # Test edge case of pid = 0 and a standard pid.
    self.assertEquals('', proc.get_cwd(0))
    self.assertEquals('/home/directory/TEST', proc.get_cwd(24019))
    
    
  def test_get_uid(self):
    """
    Tests the get_uid function with a given pid.
    """
    
    pid_list = [(24019, 11111), (0, 22222)]
    
    for pid in pid_list:
      pid_id, user_id = pid
      status_path = "/proc/%s/status" % pid_id
      mocking.mock(proc._get_line, mock_fn({(status_path, 'Uid:', 'uid'):'Uid: %s' % user_id}))
      
      self.assertEquals(user_id, proc.get_uid(pid_id))
      
  def test_get_memory_usage(self):
    """
    Tests the get_memory_usage function with a given pid.
    
    This is the only function in proc.py that calls _get_lines explicitly.
    """
    
    mocking.mock(proc._get_lines, mock_fn({('/proc/1111/status', ('VmRSS:', 'VmSize:'), 'memory usage'):{'VmRSS:':'VmRSS: 100 kB', 'VmSize:':'VmSize: 1800 kB'}}))
    
    # Test edge case of pid = 0 and a standard pid
    self.assertEqual((0,0), proc.get_memory_usage(0))
    self.assertEqual((100*1024, 1800*1024), proc.get_memory_usage(1111))
    
  def test_get_stats(self):
    """
    Tests get_stats() with all combinations of stat_type arguments.
    """
    
    # Need to bypass proc.Stat.<command> calls as they aren't in this scope.
    args = ['command', 'utime', 'stime', 'start time']
    responses = ['test_program', '0.13', '0.14', '10.21']
    
    stat_path = "/proc/24062/stat"
    stat = '1 (test_program) 2 3 4 5 6 7 8 9 10 11 12 13.0 14.0 15 16 17 18 19 20 21.0 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43'
    
    # List of all combinations of args with respective return values.
    subsets = find_subsets(zip(args, responses))
    
    mocking.mock(proc.get_system_start_time, mocking.return_value(10))
    
    
    # Tests the case where no stat_types are specified.
    mocking.mock(proc._get_line, mock_fn({(stat_path, str(24062), 'process '):stat}))
    self.assertEquals((), proc.get_stats(24062))
    
    # Don't handle empty set of commands here. (just did above)
    subsets.remove([])
    
    for sub in subsets:
      # sub = [(arg1, resp1), (arg2, resp2),...].  We need (arg1,arg2,...)
      # and (resp1,resp2,...).
      arg, response = zip(*sub)
      
      mocking.mock(proc._get_line, mock_fn({(stat_path, str(24062), 'process %s' % ', '.join(arg)):stat}))
      
      # Iterates through each combination of commands.
      self.assertEquals(response, proc.get_stats(24062, *arg))
      
    # Tests the case where pid = 0.
    for sub in subsets:
      arg, response = zip(*sub)
      if 'start time' in arg:
        response = 10
      else:
        response = ()
        for a in arg:
          if a == 'command':
            response += ('sched',)
          elif a == 'utime':
            response += ('0',)
          elif a == 'stime':
            response += ('0',)
      
      mocking.mock(proc._get_line, mock_fn({('/proc/0/stat', str(0), 'process %s' % ', '.join(arg)):stat}))
      self.assertEquals(response, proc.get_stats(0, *arg))
  
  def test_get_connections(self):
    """
    Tests the get_connections function along with a given pid.
    """
    
    pid = 1111
    fd_list = ['1', '2', '3', '4']
    
    readlink_results = ['socket:[99999999]', 'socket:[IIIIIIII]', 'pipe:[30303]', 'pipe:[40404]']
    input_vals = {}
    for i in range(len(fd_list)):
      input_vals[('/proc/%s/fd/%s' % (str(pid), fd_list[i]),)] = readlink_results[i]
    
    # Will be put in cStringIO wrappers and treated as files.
    tcp = '\n 0: 11111111:1111 22222222:2222 01 44444444:44444444 55:55555555 66666666 1111 8 99999999'
    udp = '\n A: BBBBBBBB:BBBB CCCCCCCC:CCCC DD EEEEEEEE:EEEEEEEE FF:FFFFFFFF GGGGGGGG 1111 H IIIIIIII'
    
    file_vals = {('/proc/net/tcp',):cStringIO.StringIO(tcp), ('/proc/net/udp',):cStringIO.StringIO(udp)}
    
    # Mock os.listdir, os.readlink, and open with mock_fn.
    mocking.mock(os.listdir, mock_fn({('/proc/%s/fd' % str(pid),):fd_list}, os.listdir), os)
    mocking.mock(os.readlink, mock_fn(input_vals, os.readlink), os)
    mocking.mock(open, mock_fn(file_vals, open))
    
    # Tests the edge case of pid = 0.
    self.assertEquals([], proc.get_connections(0))
    
    # First build expected responses, then call the function to be tested.
    results = []
    for keys, files in file_vals.iteritems():
      contents = files.getvalue()
      
      _, l_addr, f_addr, status, _, _, _, _, _, inode = contents.split()[:10]
      
      local_ip, local_port = proc._decode_proc_address_encoding(l_addr)
      foreign_ip, foreign_port = proc._decode_proc_address_encoding(f_addr)
      results.append((local_ip, local_port, foreign_ip, foreign_port))
      print "results: %s" % results
    self.assertEquals(results, proc.get_connections(1111))
