"""
Integration tests for stem.descriptor.reader.
"""

import os
import unittest

import stem.descriptor.reader
import test.runner

BASIC_LISTING = """
/tmp 123
/bin/grep 4567
/file with spaces/and \\ stuff 890
"""

def _get_processed_files_path():
  return os.path.join(test.runner.get_runner().get_test_dir(), "descriptor_processed_files")

def _make_processed_files_listing(contents):
  """
  Writes the given 'processed file' listing to disk, returning the path where
  it is located.
  """
  
  test_listing_path = _get_processed_files_path()
  
  test_listing_file = open(test_listing_path, "w")
  test_listing_file.write(contents)
  test_listing_file.close()
  
  return test_listing_path

class TestDescriptorReader(unittest.TestCase):
  def tearDown(self):
    # cleans up 'processed file' listings that we made
    test_listing_path = _get_processed_files_path()
    
    if os.path.exists(test_listing_path):
      os.remove(test_listing_path)
  
  def test_load_processed_files(self):
    """
    Basic sanity test for loading a processed files listing from disk.
    """
    
    test_listing_path = _make_processed_files_listing(BASIC_LISTING)
    loaded_listing = stem.descriptor.reader.load_processed_files(test_listing_path)
    
    expected_listing = {
      "/tmp": 123,
      "/bin/grep": 4567,
      "/file with spaces/and \\ stuff": 890,
    }
    
    self.assertEquals(expected_listing, loaded_listing)
  
  def test_load_processed_files_missing(self):
    """
    Tests the load_processed_files() function with a file that doesn't exist.
    """
    
    self.assertRaises(IOError, stem.descriptor.reader.load_processed_files, "/non-existant/path")
  
  def test_load_processed_files_permissions(self):
    """
    Tests the load_processed_files() function with a file that can't be read
    due to permissions.
    """
    
    test_listing_path = _make_processed_files_listing(BASIC_LISTING)
    os.chmod(test_listing_path, 0077) # remove read permissions
    self.assertRaises(IOError, stem.descriptor.reader.load_processed_files, test_listing_path)
  
  def test_save_processed_files(self):
    """
    Basic sanity test for persisting files listings to disk.
    """
    
    initial_listing = {
      "/tmp": 123,
      "/bin/grep": 4567,
      "/file with spaces/and \\ stuff": 890,
    }
    
    # saves the initial_listing to a file then reloads it
    test_listing_path = _get_processed_files_path()
    stem.descriptor.reader.save_processed_files(initial_listing, test_listing_path)
    loaded_listing = stem.descriptor.reader.load_processed_files(test_listing_path)
    
    self.assertEquals(initial_listing, loaded_listing)
  
  def test_save_processed_files_malformed(self):
    """
    Tests the save_processed_files() function with malformed data.
    """
    
    missing_filename = {"": 123}
    relative_filename = {"foobar": 123}
    string_timestamp = {"/tmp": "123a"}
    
    for listing in (missing_filename, relative_filename, string_timestamp):
      self.assertRaises(TypeError, stem.descriptor.reader.save_processed_files, listing, "/tmp/foo")

