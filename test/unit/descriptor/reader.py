"""
Unit tests for stem.descriptor.reader.
"""

import io
import unittest

import stem.descriptor.reader

from mock import patch


class TestDescriptorReader(unittest.TestCase):
  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files(self, open_mock):
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

    open_mock.return_value = io.BytesIO("\n".join(test_lines))
    self.assertEquals(expected_value, stem.descriptor.reader.load_processed_files(""))

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_empty(self, open_mock):
    """
    Tests the load_processed_files() function with an empty file.
    """

    open_mock.return_value = io.BytesIO("")
    self.assertEquals({}, stem.descriptor.reader.load_processed_files(""))

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_no_file(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the file path.
    """

    open_mock.return_value = io.BytesIO(" 12345")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_no_timestamp(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it is missing the timestamp.
    """

    open_mock.return_value = io.BytesIO("/dir/file ")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_malformed_file(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it has an invalid file path.
    """

    open_mock.return_value = io.BytesIO("not_an_absolute_file 12345")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")

  @patch('stem.descriptor.reader.open', create = True)
  def test_load_processed_files_malformed_timestamp(self, open_mock):
    """
    Tests the load_processed_files() function content that is malformed because
    it has a non-numeric timestamp.
    """

    open_mock.return_value = io.BytesIO("/dir/file 123a")
    self.assertRaises(TypeError, stem.descriptor.reader.load_processed_files, "")
