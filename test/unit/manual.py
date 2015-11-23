"""
Unit testing for the stem.manual module.
"""

import io
import unittest

import stem.prereq
import stem.manual

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

URL_OPEN = 'urllib.request.urlopen' if stem.prereq.is_python_3() else 'urllib2.urlopen'


class TestManual(unittest.TestCase):
  def test_is_important(self):
    self.assertTrue(stem.manual.is_important('ExitPolicy'))
    self.assertTrue(stem.manual.is_important('exitpolicy'))
    self.assertTrue(stem.manual.is_important('EXITPOLICY'))

    self.assertFalse(stem.manual.is_important('ConstrainedSockSize'))

  def test_download_man_page_without_arguments(self):
    try:
      stem.manual.download_man_page()
      self.fail('we should fail without a path or file handler')
    except ValueError as exc:
      self.assertEqual("Either the path or file_handle we're saving to must be provided", str(exc))

  @patch('stem.util.system.is_available', Mock(return_value = False))
  def test_download_man_page_requires_a2x(self):
    try:
      stem.manual.download_man_page('/tmp/no_such_file')
      self.fail('we should require a2x to be available')
    except IOError as exc:
      self.assertEqual('We require a2x from asciidoc to provide a man page', str(exc))

  @patch('tempfile.mkdtemp', Mock(return_value = '/no/such/path'))
  @patch('shutil.rmtree', Mock())
  @patch('stem.manual.open', Mock(side_effect = IOError('unable to write to file')), create = True)
  def test_download_man_page_when_unable_to_write(self):
    try:
      stem.manual.download_man_page('/tmp/no_such_file')
      self.fail("we shouldn't be able to write to /no/such/path")
    except IOError as exc:
      self.assertEqual("Unable to download tor's manual from https://gitweb.torproject.org/tor.git/plain/doc/tor.1.txt to /no/such/path/tor.1.txt: unable to write to file", str(exc))

  @patch('tempfile.mkdtemp', Mock(return_value = '/no/such/path'))
  @patch('shutil.rmtree', Mock())
  @patch('stem.manual.open', Mock(return_value = io.BytesIO()), create = True)
  @patch(URL_OPEN, Mock(side_effect = urllib.URLError('<urlopen error [Errno -2] Name or service not known>')))
  def test_download_man_page_when_download_fails(self):
    try:
      stem.manual.download_man_page('/tmp/no_such_file', url = 'https://www.atagar.com/foo/bar')
      self.fail("downloading from test_invalid_url.org shouldn't work")
    except IOError as exc:
      self.assertEqual("Unable to download tor's manual from https://www.atagar.com/foo/bar to /no/such/path/tor.1.txt: <urlopen error <urlopen error [Errno -2] Name or service not known>>", str(exc))

  @patch('tempfile.mkdtemp', Mock(return_value = '/no/such/path'))
  @patch('shutil.rmtree', Mock())
  @patch('stem.manual.open', Mock(return_value = io.BytesIO()), create = True)
  @patch('stem.util.system.call', Mock(side_effect = OSError('call failed')))
  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'test content')))
  def test_download_man_page_when_a2x_fails(self):
    try:
      stem.manual.download_man_page('/tmp/no_such_file', url = 'https://www.atagar.com/foo/bar')
      self.fail("downloading from test_invalid_url.org shouldn't work")
    except IOError as exc:
      self.assertEqual("Unable to run 'a2x -f manpage /no/such/path/tor.1.txt': call failed", str(exc))

  @patch('tempfile.mkdtemp', Mock(return_value = '/no/such/path'))
  @patch('shutil.rmtree', Mock())
  @patch('stem.manual.open', create = True)
  @patch('stem.util.system.call')
  @patch('os.path.exists', Mock(return_value = True))
  @patch(URL_OPEN, Mock(return_value = io.BytesIO(b'test content')))
  def test_download_man_page_when_successful(self, call_mock, open_mock):
    open_mock.side_effect = lambda path, *args: {
      '/no/such/path/tor.1.txt': io.BytesIO(),
      '/no/such/path/tor.1': io.BytesIO(b'a2x output'),
    }[path]

    call_mock.return_value = Mock()

    output = io.BytesIO()
    stem.manual.download_man_page(file_handle = output)
    self.assertEqual(b'a2x output', output.getvalue())
    call_mock.assert_called_once_with('a2x -f manpage /no/such/path/tor.1.txt')

  @patch('stem.util.system.call', Mock(side_effect = OSError('man -P cat tor returned exit status 16')))
  def test_from_man_when_manual_is_unavailable(self):
    try:
      stem.manual.Manual.from_man()
      self.fail("fetching the manual should fail when it's unavailable")
    except IOError as exc:
      self.assertEqual("Unable to run 'man -P cat tor': man -P cat tor returned exit status 16", str(exc))

  @patch('stem.util.system.call', Mock(return_value = []))
  def test_when_man_is_empty(self):
    manual = stem.manual.Manual.from_man()

    self.assertEqual('', manual.name)
    self.assertEqual('', manual.synopsis)
    self.assertEqual('', manual.description)
    self.assertEqual({}, manual.commandline_options)
    self.assertEqual({}, manual.signals)
    self.assertEqual({}, manual.files)
    self.assertEqual(OrderedDict(), manual.config_options)
