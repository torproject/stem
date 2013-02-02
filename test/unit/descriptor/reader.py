"""
Unit tests for stem.descriptor.reader.
"""

import StringIO
import unittest

import stem.descriptor.reader
import stem.prereq
import test.mocking as mocking


def _mock_open(content):
  test_content = StringIO.StringIO(content)
  mocking.support_with(test_content)

  if stem.prereq.is_python_3():
    import builtins
    mocking.mock(builtins.open, mocking.return_value(test_content), builtins)
  else:
    mocking.mock(open, mocking.return_value(test_content))


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

    _mock_open("\n".join(test_lines))
    self.assertEquals(expected_value, stem.descriptor.reader.load_processed_files(""))

  def test_load_processed_files_empty(self):
    """
    Tests the load_processed_files() function with an empty file.
    """

    _mock_open("")
    self.assertEquals({}, stem.descriptor.reader.load_processed_files(""))

  def test_load_processed_files_no_file(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the file path.
    """

    _mock_open(" 12345")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")

  def test_load_processed_files_no_timestamp(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the timestamp.
    """

    _mock_open("/dir/file ")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")

  def test_load_processed_files_malformed_file(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it has an invalid file path.
    """

    _mock_open("not_an_absolute_file 12345")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")

  def test_load_processed_files_malformed_timestamp(self):
    """
    Tests the load_processed_files() function content that is malformed because
    it has a non-numeric timestamp.
    """

    _mock_open("/dir/file 123a")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")
