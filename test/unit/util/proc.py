"""
Unit testing code for proc utilities located in /stem/util/proc.py
"""
import os
import time
import unittest
import functools

import test.mocking as mocking
import stem.util.proc as proc

def mock_get_lines(file_path, line_prefixes, return_values):
  """
  Provides mocking for the proc module's _get_line function.
  """
  if isinstance(line_prefixes, tuple):
      prefix_list = sorted(list(line_prefixes))
  else:
      # Only one line prefix given.
      prefix_list = line_prefixes
  def _mock_get_lines(path, prefixes, return_values, caller_path,
  caller_prefixes, caller_parameter):
      if isinstance(caller_prefixes, tuple):
          caller_prefix_list = sorted(list(caller_prefixes))
      else:
          #Only one line prefix given.
          caller_prefix_list = caller_prefixes
      if path == caller_path and prefixes == caller_prefix_list:
          return return_values
      else:
          return None
  
  return functools.partial(_mock_get_lines, file_path, prefix_list,
  return_values)

class TestProc(unittest.TestCase):
  def tearDown(self):
      mocking.revert_mocking()
  
  def test_get_system_start_time(self):
      """
      Tests the get_system_start_time function.
      """
      mocking.mock(proc._get_line, mock_get_lines("/proc/stat", "btime",
      "btime 1001001"))
      
      self.assertEquals(1001001, proc.get_system_start_time())
  
  def test_get_physical_memory(self):
      """
      Tests the get_physical_memory function.
      """
      mocking.mock(proc._get_line, mock_get_lines("/proc/meminfo",
      "MemTotal:", "MemTotal:       12345 kB"))
      
      self.assertEquals((12345*1024), proc.get_physical_memory())
  
  def test_get_memory_usage(self):
      """
      Tests the get_memory_usage function.
      
      This is the only function in proc.py that utilizes
      _get_lines explicitly.
      """
      
      mocking.mock(proc._get_lines, mock_get_lines("/proc/1111/status",
      ("VmRSS:", "VmSize:"), {"VmRSS:": "VmRSS: 100 kB",
      "VmSize:":"VmSize: 1800 kB"}))
      
      self.assertEqual((100*1024, 1800*1024), proc.get_memory_usage(1111))
