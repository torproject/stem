"""
Unit tests for stem.descriptor.reader.
"""

import StringIO
import unittest

import stem.descriptor.reader
import test.mocking as mocking

class TestDescriptorReader(unittest.TestCase):
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_load_processed_files(self):
    """
    Successful load of content.
    """
    
    test_lines = (
      "/dir/ 0",
      "/dir/file 12345",
      "/dir/file with spaces 7138743",
      "  /dir/with extra space 12345   ",
      "   \t   ",
      "",
      "/dir/after empty line 12345",
    )
    
    expected_value = {
      "/dir/": 0,
      "/dir/file": 12345,
      "/dir/file with spaces": 7138743,
      "/dir/with extra space": 12345,
      "/dir/after empty line": 12345,
    }
    
    test_content = StringIO.StringIO("\n".join(test_lines))
    mocking.support_with(test_content)
    mocking.mock(open, mocking.return_value(test_content))
    self.assertEquals(expected_value, stem.descriptor.reader.load_processed_files(""))
  
  def test_load_processed_files_empty(self):
    """
    Tests the load_processed_files() function with an empty file.
    """
    
    test_content = StringIO.StringIO("")
    mocking.support_with(test_content)
    mocking.mock(open, mocking.return_value(test_content))
    self.assertEquals({}, stem.descriptor.reader.load_processed_files(""))
  
  def test_load_processed_files_no_file(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the file path.
    """
    
    test_content = StringIO.StringIO(" 12345")
    mocking.support_with(test_content)
    mocking.mock(open, mocking.return_value(test_content))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")
  
  def test_load_processed_files_no_timestamp(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the timestamp.
    """
    
    test_content = StringIO.StringIO("/dir/file ")
    mocking.support_with(test_content)
    mocking.mock(open, mocking.return_value(test_content))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")
  
  def test_load_processed_files_malformed_file(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it has an invalid file path.
    """
    
    test_content = StringIO.StringIO("not_an_absolute_file 12345")
    mocking.support_with(test_content)
    mocking.mock(open, mocking.return_value(test_content))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")
  
  def test_load_processed_files_malformed_timestamp(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it has a non-numeric timestamp.
    """
    
    test_content = StringIO.StringIO("/dir/file 123a")
    mocking.support_with(test_content)
    mocking.mock(open, mocking.return_value(test_content))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")
