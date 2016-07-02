"""
Unit tests for stem.descriptor.reader.
"""

import getpass
import io
import os
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import unittest

import stem.descriptor.reader
import test.runner
import test.unit.descriptor

from stem.util import str_type, system

try:
  # added in python 3.3
  from unittest.mock import patch
except ImportError:
  from mock import patch

BASIC_LISTING = """
/tmp 123
/bin/grep 4567
/file with spaces/and \\ stuff 890
"""

my_dir = os.path.dirname(__file__)
DESCRIPTOR_TEST_DATA = os.path.join(my_dir, 'data')

TAR_DESCRIPTORS = None


def _get_raw_tar_descriptors():
  global TAR_DESCRIPTORS

  if not TAR_DESCRIPTORS:
    test_path = os.path.join(DESCRIPTOR_TEST_DATA, 'descriptor_archive.tar')
    raw_descriptors = []

    # TODO: revert to using the 'with' keyword for this when dropping python
    # 2.6 support

    tar_file = None

    try:
      tar_file = tarfile.open(test_path)

      for tar_entry in tar_file:
        if tar_entry.isfile():
          entry = tar_file.extractfile(tar_entry)
          entry.readline()  # strip header
          raw_descriptors.append(entry.read().decode('utf-8', 'replace'))
          entry.close()
    finally:
      if tar_file:
        tar_file.close()

    TAR_DESCRIPTORS = raw_descriptors

  return TAR_DESCRIPTORS


class SkipListener:
  def __init__(self):
    self.results = []  # (path, exception) tuples that we've received

  def listener(self, path, exception):
    self.results.append((path, exception))


class TestDescriptorReader(unittest.TestCase):
  def setUp(self):
    self.temp_directory = tempfile.mkdtemp()
    self.test_listing_path = os.path.join(self.temp_directory, 'descriptor_processed_files')

  def tearDown(self):
    shutil.rmtree(self.temp_directory)

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files(self, open_mock):
    """
    Successful load of content.
    """

    test_lines = (
      str_type('/dir/ 0'),
      str_type('/dir/file 12345'),
      str_type('/dir/file with spaces 7138743'),
      str_type('  /dir/with extra space 12345   '),
      str_type('   \t   '),
      str_type(''),
      str_type('/dir/after empty line 12345'),
    )

    expected_value = {
      '/dir/': 0,
      '/dir/file': 12345,
      '/dir/file with spaces': 7138743,
      '/dir/with extra space': 12345,
      '/dir/after empty line': 12345,
    }

    open_mock.return_value = io.StringIO(str_type('\n'.join(test_lines)))
    self.assertEqual(expected_value, stem.descriptor.reader.load_processed_files(''))

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_empty(self, open_mock):
    """
    Tests the load_processed_files() function with an empty file.
    """

    open_mock.return_value = io.StringIO(str_type(''))
    self.assertEqual({}, stem.descriptor.reader.load_processed_files(''))

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_no_file(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the file path.
    """

    open_mock.return_value = io.StringIO(str_type(' 12345'))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, '')

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_no_timestamp(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the timestamp.
    """

    open_mock.return_value = io.StringIO(str_type('/dir/file '))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, '')

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_malformed_file(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it has an invalid file path.
    """

    open_mock.return_value = io.StringIO(str_type('not_an_absolute_file 12345'))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, '')

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_malformed_timestamp(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it has a non-numeric timestamp.
    """

    open_mock.return_value = io.StringIO(str_type('/dir/file 123a'))
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, '')

  def test_load_processed_files_from_data(self):
    """
    Basic sanity test for loading a processed files listing from disk.
    """

    test_listing_path = self._make_processed_files_listing(BASIC_LISTING)
    loaded_listing = stem.descriptor.reader.load_processed_files(test_listing_path)

    expected_listing = {
      '/tmp': 123,
      '/bin/grep': 4567,
      '/file with spaces/and \\ stuff': 890,
    }

    self.assertEqual(expected_listing, loaded_listing)

  def test_load_processed_files_missing(self):
    """
    Tests the load_processed_files() function with a file that doesn't exist.
    """

    self.assertRaises(IOError, stem.descriptor.reader.load_processed_files, '/non-existant/path')

  def test_load_processed_files_permissions(self):
    """
    Tests the load_processed_files() function with a file that can't be read
    due to permissions.
    """

    # test relies on being unable to read a file

    if getpass.getuser() == 'root':
      test.runner.skip(self, '(running as root)')
      return

    # Skip the test on windows, since you can only set the file's
    # read-only flag with os.chmod(). For more information see...
    # http://docs.python.org/library/os.html#os.chmod

    if system.is_windows():
      test.runner.skip(self, '(chmod not functional)')

    test_listing_path = self._make_processed_files_listing(BASIC_LISTING)
    os.chmod(test_listing_path, 0o077)  # remove read permissions
    self.assertRaises(IOError, stem.descriptor.reader.load_processed_files, test_listing_path)

  def test_save_processed_files(self):
    """
    Basic sanity test for persisting files listings to disk.
    """

    initial_listing = {
      '/tmp': 123,
      '/bin/grep': 4567,
      '/file with spaces/and \\ stuff': 890,
    }

    # saves the initial_listing to a file then reloads it

    stem.descriptor.reader.save_processed_files(self.test_listing_path, initial_listing)
    loaded_listing = stem.descriptor.reader.load_processed_files(self.test_listing_path)

    self.assertEqual(initial_listing, loaded_listing)

  def test_save_processed_files_malformed(self):
    """
    Tests the save_processed_files() function with malformed data.
    """

    missing_filename = {'': 123}
    relative_filename = {'foobar': 123}
    string_timestamp = {'/tmp': '123a'}
    temp_path = tempfile.mkstemp(prefix = 'stem-unit-tests-', text = True)[1]

    for listing in (missing_filename, relative_filename, string_timestamp):
      self.assertRaises(TypeError, stem.descriptor.reader.save_processed_files, temp_path, listing)

    # Though our attempts to save the processed files fail we'll write an empty
    # file. Cleaning it up.

    try:
      os.remove(temp_path)
    except:
      pass

  def test_basic_example(self):
    """
    Exercises something similar to the first example in the header
    documentation, checking that some of the contents match what we'd expect.
    """

    # snag some of the plaintext descriptors so we can later make sure that we
    # iterate over them

    descriptor_entries = []

    descriptor_path = os.path.join(DESCRIPTOR_TEST_DATA, 'example_descriptor')

    with open(descriptor_path) as descriptor_file:
      descriptor_file.readline()  # strip header
      descriptor_entries.append(descriptor_file.read())

    # running this test multiple times to flush out concurrency issues

    for _ in range(15):
      remaining_entries = list(descriptor_entries)

      with stem.descriptor.reader.DescriptorReader(descriptor_path) as reader:
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

    descriptor_path = os.path.join(DESCRIPTOR_TEST_DATA, 'example_descriptor')
    reader = stem.descriptor.reader.DescriptorReader(descriptor_path)

    with reader:
      self.assertEqual(1, len(list(reader)))

    # run it a second time, this shouldn't provide any descriptors because we
    # have already read it

    with reader:
      self.assertEqual(0, len(list(reader)))

    # clear the DescriptorReader's memory of seeing the file and run it again

    reader.set_processed_files([])

    with reader:
      self.assertEqual(1, len(list(reader)))

  def test_buffer_size(self):
    """
    Checks that we can process sets of descriptors larger than our buffer size,
    that we don't exceed it, and that we can still stop midway through reading
    them.
    """

    reader = stem.descriptor.reader.DescriptorReader(DESCRIPTOR_TEST_DATA, buffer_size = 2)

    with reader:
      self.assertTrue(reader.get_buffered_descriptor_count() <= 2)
      time.sleep(0.01)
      self.assertTrue(reader.get_buffered_descriptor_count() <= 2)

  def test_persistence_path(self):
    """
    Check that the persistence_path argument loads and saves a a processed
    files listing.
    """

    descriptor_path = os.path.join(DESCRIPTOR_TEST_DATA, 'example_descriptor')

    # First run where the persistence_path doesn't yet exist. This just tests
    # the saving functionality.

    reader = stem.descriptor.reader.DescriptorReader(descriptor_path, persistence_path = self.test_listing_path)

    with reader:
      self.assertEqual(1, len(list(reader)))

    # check that we've saved reading example_descriptor
    self.assertTrue(os.path.exists(self.test_listing_path))

    with open(self.test_listing_path) as persistence_file:
      persistance_file_contents = persistence_file.read()
      self.assertTrue(persistance_file_contents.startswith(descriptor_path))

    # Try running again with a new reader but the same persistance path, if it
    # reads and takes the persistence_path into account then it won't read the
    # descriptor file. This in essence just tests its loading functionality.

    reader = stem.descriptor.reader.DescriptorReader(descriptor_path, persistence_path = self.test_listing_path)

    with reader:
      self.assertEqual(0, len(list(reader)))

  def test_archived_paths(self):
    """
    Checks the get_path() and get_archive_path() for a tarball.
    """

    expected_archive_paths = (
      'descriptor_archive/0/2/02c311d3d789f3f55c0880b5c85f3c196343552c',
      'descriptor_archive/1/b/1bb798cae15e21479db0bc700767eee4733e9d4a',
      'descriptor_archive/1/b/1ef75fef564180d8b3f72c6f8635ff0cd855f92c',
    )

    test_path = os.path.join(DESCRIPTOR_TEST_DATA, 'descriptor_archive.tar')

    with stem.descriptor.reader.DescriptorReader(test_path) as reader:
      for desc in reader:
        self.assertEqual(test_path, desc.get_path())
        self.assertTrue(desc.get_archive_path() in expected_archive_paths)

  def test_archived_uncompressed(self):
    """
    Checks that we can read descriptors from an uncompressed archive.
    """

    expected_results = _get_raw_tar_descriptors()
    test_path = os.path.join(DESCRIPTOR_TEST_DATA, 'descriptor_archive.tar')

    with stem.descriptor.reader.DescriptorReader(test_path) as reader:
      read_descriptors = [str(desc) for desc in list(reader)]
      self.assertEqual(expected_results, read_descriptors)

  def test_archived_gzip(self):
    """
    Checks that we can read descriptors from a gzipped archive.
    """

    expected_results = _get_raw_tar_descriptors()
    test_path = os.path.join(DESCRIPTOR_TEST_DATA, 'descriptor_archive.tar.gz')

    with stem.descriptor.reader.DescriptorReader(test_path) as reader:
      read_descriptors = [str(desc) for desc in list(reader)]
      self.assertEqual(expected_results, read_descriptors)

  def test_archived_bz2(self):
    """
    Checks that we can read descriptors from an bzipped archive.
    """

    expected_results = _get_raw_tar_descriptors()
    test_path = os.path.join(DESCRIPTOR_TEST_DATA, 'descriptor_archive.tar.bz2')

    with stem.descriptor.reader.DescriptorReader(test_path) as reader:
      read_descriptors = [str(desc) for desc in list(reader)]
      self.assertEqual(expected_results, read_descriptors)

  def test_stop(self):
    """
    Runs a DescriptorReader over the root directory, then checks that calling
    stop() makes it terminate in a timely fashion.
    """

    # Skip on windows since SIGALRM is unavailable

    if system.is_windows():
      test.runner.skip(self, '(SIGALRM unavailable)')

    is_test_running = True
    reader = stem.descriptor.reader.DescriptorReader('/usr')

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
        last_modified = int(os.stat(path).st_mtime)
        expected_results[path] = last_modified

    reader = stem.descriptor.reader.DescriptorReader(DESCRIPTOR_TEST_DATA)

    with reader:
      list(reader)  # iterates over all of the descriptors

    self.assertEqual(expected_results, reader.get_processed_files())

  def test_skip_nondescriptor_contents(self):
    """
    Checks that the reader properly reports when it skips both binary and
    plaintext non-descriptor files.
    """

    skip_listener = SkipListener()
    reader = stem.descriptor.reader.DescriptorReader(DESCRIPTOR_TEST_DATA)
    reader.register_skip_listener(skip_listener.listener)

    expected_skip_files = ('riddle', 'tiny.png', 'vote', 'new_metrics_type', 'cached-microdesc-consensus_with_carriage_returns', 'extrainfo_nonascii_v3_reqs')

    with reader:
      list(reader)  # iterates over all of the descriptors

    # strip anything with a .swp suffix (vim tmp files)

    skip_listener.results = [(path, exc) for (path, exc) in skip_listener.results if not path.endswith('.swp')]

    if len(skip_listener.results) != len(expected_skip_files):
      expected_label = ',\n  '.join(expected_skip_files)
      results_label = ',\n  '.join(['%s (%s)' % (path, exc) for (path, exc) in skip_listener.results])

      self.fail('Skipped files that we should have been able to parse.\n\nExpected:\n  %s\n\nResult:\n  %s' % (expected_label, results_label))

    for skip_path, skip_exception in skip_listener.results:
      if not os.path.basename(skip_path) in expected_skip_files:
        self.fail('Unexpected non-descriptor content: %s' % skip_path)

      self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.UnrecognizedType))

  def test_skip_listener_already_read(self):
    """
    Checks that calling set_processed_files() prior to reading makes us skip
    those files. This also doubles for testing that skip listeners are notified
    of files that we've already read.
    """

    # path that we want the DescriptorReader to skip

    test_path = os.path.join(DESCRIPTOR_TEST_DATA, 'example_descriptor')
    initial_processed_files = {test_path: sys.maxsize}

    skip_listener = SkipListener()
    reader = stem.descriptor.reader.DescriptorReader(test_path)
    reader.register_skip_listener(skip_listener.listener)
    reader.set_processed_files(initial_processed_files)

    self.assertEqual(initial_processed_files, reader.get_processed_files())

    with reader:
      list(reader)  # iterates over all of the descriptors

    self.assertEqual(1, len(skip_listener.results))

    skipped_path, skip_exception = skip_listener.results[0]
    self.assertEqual(test_path, skipped_path)
    self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.AlreadyRead))
    self.assertEqual(sys.maxsize, skip_exception.last_modified_when_read)

  def test_skip_listener_unrecognized_type(self):
    """
    Listens for a file that's skipped because its file type isn't recognized.
    """

    # types are solely based on file extensions so making something that looks
    # like an png image

    test_path = os.path.join(self.temp_directory, 'test.png')

    try:
      test_file = open(test_path, 'w')
      test_file.write('test data for test_skip_listener_unrecognized_type()')
      test_file.close()

      skip_listener = SkipListener()
      reader = stem.descriptor.reader.DescriptorReader(test_path)
      reader.register_skip_listener(skip_listener.listener)

      with reader:
        list(reader)  # iterates over all of the descriptors

      self.assertEqual(1, len(skip_listener.results))

      skipped_path, skip_exception = skip_listener.results[0]
      self.assertEqual(test_path, skipped_path)
      self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.UnrecognizedType))
      self.assertTrue(skip_exception.mime_type in (('image/png', None), ('image/x-png', None)))
    finally:
      if os.path.exists(test_path):
        os.remove(test_path)

  def test_skip_listener_read_failure(self):
    """
    Listens for a file that's skipped because we lack read permissions.
    """

    # test relies on being unable to read a file

    if getpass.getuser() == 'root':
      test.runner.skip(self, '(running as root)')
      return
    elif system.is_windows():
      test.runner.skip(self, '(chmod not functional)')
      return

    test_path = os.path.join(self.temp_directory, 'secret_file')

    try:
      test_file = open(test_path, 'w')
      test_file.write('test data for test_skip_listener_unrecognized_type()')
      test_file.close()

      os.chmod(test_path, 0o077)  # remove read permissions

      skip_listener = SkipListener()
      reader = stem.descriptor.reader.DescriptorReader(test_path)
      reader.register_skip_listener(skip_listener.listener)

      with reader:
        list(reader)  # iterates over all of the descriptors

      self.assertEqual(1, len(skip_listener.results))

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

    test_path = '/non-existant/path'

    skip_listener = SkipListener()
    reader = stem.descriptor.reader.DescriptorReader(test_path)
    reader.register_skip_listener(skip_listener.listener)

    with reader:
      list(reader)  # iterates over all of the descriptors

    self.assertEqual(1, len(skip_listener.results))

    skipped_path, skip_exception = skip_listener.results[0]
    self.assertEqual(test_path, skipped_path)
    self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.FileMissing))

  def test_unrecognized_metrics_type(self):
    """
    Parses a file that has a valid metrics header, but an unrecognized type.
    """

    test_path = test.unit.descriptor.get_resource('new_metrics_type')

    skip_listener = SkipListener()
    reader = stem.descriptor.reader.DescriptorReader(test_path)
    reader.register_skip_listener(skip_listener.listener)

    with reader:
      list(reader)  # iterates over all of the descriptors

    self.assertEqual(1, len(skip_listener.results))

    skipped_path, skip_exception = skip_listener.results[0]
    self.assertEqual(test_path, skipped_path)
    self.assertTrue(isinstance(skip_exception, stem.descriptor.reader.UnrecognizedType))
    self.assertEqual((None, None), skip_exception.mime_type)

  def _make_processed_files_listing(self, contents):
    """
    Writes the given 'processed file' listing to disk, returning the path where
    it is located.
    """

    with open(self.test_listing_path, 'w') as test_listing_file:
      test_listing_file.write(contents)

    return self.test_listing_path
