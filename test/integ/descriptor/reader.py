"""
Integration tests for stem.descriptor.reader.
"""

import os
import sys
import time
import signal
import unittest

import stem.descriptor.reader
import test.runner

BASIC_LISTING = """
/tmp 123
/bin/grep 4567
/file with spaces/and \\ stuff 890
"""

my_dir = os.path.dirname(__file__)
DESCRIPTOR_TEST_DATA = os.path.join(my_dir, "data")

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

class SkipListener:
  def __init__(self):
    self.results = [] # (path, exception) tuples that we've received
  
  def listener(self, path, exception):
    self.results.append((path, exception))

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
  
  def test_basic_example(self):
    """
    Exercises something similar to the first example in the header
    documentation, checking that some of the contents match what we'd expect.
    """
    
    # snag some of the plaintext descriptors so we can later make sure that we
    # iterate over them
    
    descriptor_entries = []
    
    descriptor_path = os.path.join(DESCRIPTOR_TEST_DATA, "example_descriptor")
    with open(descriptor_path) as descriptor_file:
      descriptor_entries.append(descriptor_file.read())
    
    # running this test multiple times to flush out concurrency issues
    for i in xrange(15):
      reader = stem.descriptor.reader.DescriptorReader([DESCRIPTOR_TEST_DATA])
      remaining_entries = list(descriptor_entries)
      
      with reader:
        for descriptor in reader:
          descriptor_str = str(descriptor)
          
          if descriptor_str in remaining_entries:
            remaining_entries.remove(descriptor_str)
          else:
            # iterator is providing output that we didn't expect
            self.fail()
      
      # check that we've seen all of the descriptor_entries
      self.assertTrue(len(remaining_entries) == 0)
  
  def test_multiple_runs(self):
    """
    Runs a DescriptorReader instance multiple times over the same content,
    making sure that it can be used repeatedly.
    """
    
    descriptor_path = os.path.join(DESCRIPTOR_TEST_DATA, "example_descriptor")
    reader = stem.descriptor.reader.DescriptorReader([descriptor_path])
    
    with reader:
      self.assertEquals(len(list(reader)), 1)
    
    # run it a second time, this shouldn't provide any descriptors because we
    # have already read it
    
    with reader:
      self.assertEquals(len(list(reader)), 0)
    
    # clear the DescriptorReader's memory of seeing the file and run it again
    
    reader.set_processed_files([])
    
    with reader:
      self.assertEquals(len(list(reader)), 1)
  
  def test_stop(self):
    """
    Runs a DescriptorReader over the root directory, then checks that calling
    stop() makes it terminate in a timely fashion.
    """
    
    is_test_running = True
    reader = stem.descriptor.reader.DescriptorReader(["/"])
    
    # Fails the test after a couple seconds if we don't finish successfully.
    # Depending on what we're blocked on this might not work when the test
    # fails, requiring that we give a manual kill to the test.
    
    def timeout_handler(signum, frame):
      if is_test_running:
        self.fail()
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(2)
    
    reader.start()
    time.sleep(0.1)
    reader.stop()
    is_test_running = False
  
  def test_get_processed_files(self):
    """
    Checks that get_processed_files() provides the expected results after
    iterating over our test data.
    """
    
    expected_results = {}
    
    for root, _, files in os.walk(DESCRIPTOR_TEST_DATA):
      for filename in files:
        path = os.path.join(root, filename)
        last_modified = os.stat(path).st_mtime
        expected_results[path] = last_modified
    
    reader = stem.descriptor.reader.DescriptorReader([DESCRIPTOR_TEST_DATA])
    with reader: list(reader) # iterates over all of the descriptors
    
    self.assertEquals(expected_results, reader.get_processed_files())
  
  def test_set_processed_files(self):
    """
    Checks that calling set_processed_files() prior to reading makes us skip
    those files.
    """
    
    # path and file contents that we want the DescriptorReader to skip
    skip_file = os.path.join(DESCRIPTOR_TEST_DATA, "example_descriptor")
    
    with open(skip_file) as descriptor_file:
      skip_contents = descriptor_file.read()
    
    initial_processed_files = {skip_file: sys.maxint}
    
    reader = stem.descriptor.reader.DescriptorReader([DESCRIPTOR_TEST_DATA])
    reader.set_processed_files(initial_processed_files)
    self.assertEquals(initial_processed_files, reader.get_processed_files())
    
    with reader:
      for descriptor in reader:
        if str(descriptor) == skip_contents:
          self.fail() # we read the file that we were trying to skip
  
  def test_skip_listener_unrecognized_type(self):
    """
    Listens for a file that's skipped because its file type isn't recognized.
    """
    
    # types are solely based on file extensions so making something that looks
    # like an png image
    
    test_path = os.path.join(test.runner.get_runner().get_test_dir(), "test.png")
    
    with open(test_path, "w") as test_file:
      test_file.write("test data for test_skip_listener_unrecognized_type()")
    
    try:
      skip_listener = SkipListener()
      reader = stem.descriptor.reader.DescriptorReader([test_path])
      reader.register_skip_listener(skip_listener.listener)
      with reader: list(reader) # iterates over all of the descriptors
      
      self.assertTrue(len(skip_listener.results) == 1)
      
      skipped_path, skip_exception = skip_listener.results[0]
      self.assertEqual(test_path, skipped_path)
      self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.UnrecognizedType))
      self.assertEqual(("image/png", None), skip_exception.mime_type)
    finally:
      if os.path.exists(test_path):
        os.remove(test_path)
  
  def test_skip_listener_read_failure(self):
    """
    Listens for a file that's skipped because we lack read permissions.
    """
    
    test_path = os.path.join(test.runner.get_runner().get_test_dir(), "secret_file")
    
    with open(test_path, "w") as test_file:
      test_file.write("test data for test_skip_listener_unrecognized_type()")
    
    os.chmod(test_path, 0077) # remove read permissions
    
    try:
      skip_listener = SkipListener()
      reader = stem.descriptor.reader.DescriptorReader([test_path])
      reader.register_skip_listener(skip_listener.listener)
      with reader: list(reader) # iterates over all of the descriptors
      
      self.assertTrue(len(skip_listener.results) == 1)
      
      skipped_path, skip_exception = skip_listener.results[0]
      self.assertEqual(test_path, skipped_path)
      self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.ReadFailed))
      self.assertTrue(isinstance(skip_exception.exception, IOError))
    finally:
      if os.path.exists(test_path):
        os.remove(test_path)
  
  def test_skip_listener_file_missing(self):
    """
    Listens for a file that's skipped because the file doesn't exist.
    """
    
    test_path = "/foo/bar/doesn't_exist"
    
    skip_listener = SkipListener()
    reader = stem.descriptor.reader.DescriptorReader([test_path])
    reader.register_skip_listener(skip_listener.listener)
    with reader: list(reader) # iterates over all of the descriptors
    
    self.assertTrue(len(skip_listener.results) == 1)
    
    skipped_path, skip_exception = skip_listener.results[0]
    self.assertEqual(test_path, skipped_path)
    self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.FileMissing))

