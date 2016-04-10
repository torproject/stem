"""
Unit tests for the stem.util.str_tools functions.
"""

import datetime
import unittest

from stem.util import str_tools


class TestStrTools(unittest.TestCase):
  def test_to_camel_case(self):
    """
    Checks the _to_camel_case() function.
    """

    # test the pydoc example
    self.assertEqual('I Like Pepperjack!', str_tools._to_camel_case('I_LIKE_PEPPERJACK!'))

    # check a few edge cases
    self.assertEqual('', str_tools._to_camel_case(''))
    self.assertEqual('Hello', str_tools._to_camel_case('hello'))
    self.assertEqual('Hello', str_tools._to_camel_case('HELLO'))
    self.assertEqual('Hello  World', str_tools._to_camel_case('hello__world'))
    self.assertEqual('Hello\tworld', str_tools._to_camel_case('hello\tWORLD'))
    self.assertEqual('Hello\t\tWorld', str_tools._to_camel_case('hello__world', '_', '\t'))

  def test_crop(self):
    # test the pydoc examples
    self.assertEqual('This is a looo...', str_tools.crop('This is a looooong message', 17))
    self.assertEqual('This is a...', str_tools.crop('This is a looooong message', 12))
    self.assertEqual('', str_tools.crop('This is a looooong message', 3))
    self.assertEqual('', str_tools.crop('This is a looooong message', 0))

  def test_size_label(self):
    """
    Checks the size_label() function.
    """

    # test the pydoc examples
    self.assertEqual('1 MB', str_tools.size_label(2000000))
    self.assertEqual('1.02 KB', str_tools.size_label(1050, 2))
    self.assertEqual('1.025 Kilobytes', str_tools.size_label(1050, 3, True))

    self.assertEqual('0 B', str_tools.size_label(0))
    self.assertEqual('0 Bytes', str_tools.size_label(0, is_long = True))
    self.assertEqual('0.00 B', str_tools.size_label(0, 2))
    self.assertEqual('-10 B', str_tools.size_label(-10))
    self.assertEqual('80 b', str_tools.size_label(10, is_bytes = False))
    self.assertEqual('-1 MB', str_tools.size_label(-2000000))

    # checking that we round down
    self.assertEqual('23.43 Kb', str_tools.size_label(3000, 2, is_bytes = False))

    self.assertRaises(TypeError, str_tools.size_label, None)
    self.assertRaises(TypeError, str_tools.size_label, 'hello world')

  def test_time_label(self):
    """
    Checks the time_label() function.
    """

    # test the pydoc examples
    self.assertEqual('2h', str_tools.time_label(10000))
    self.assertEqual('1.0 minute', str_tools.time_label(61, 1, True))
    self.assertEqual('1.01 minutes', str_tools.time_label(61, 2, True))

    self.assertEqual('0s', str_tools.time_label(0))
    self.assertEqual('0 seconds', str_tools.time_label(0, is_long = True))
    self.assertEqual('0.00s', str_tools.time_label(0, 2))
    self.assertEqual('-10s', str_tools.time_label(-10))

    self.assertRaises(TypeError, str_tools.time_label, None)
    self.assertRaises(TypeError, str_tools.time_label, 'hello world')

  def test_time_labels(self):
    """
    Checks the time_labels() function.
    """

    # test the pydoc examples
    self.assertEqual(['6m', '40s'], str_tools.time_labels(400))
    self.assertEqual(['1 hour', '40 seconds'], str_tools.time_labels(3640, True))

    self.assertEqual([], str_tools.time_labels(0))
    self.assertEqual(['-10s'], str_tools.time_labels(-10))

    self.assertRaises(TypeError, str_tools.time_labels, None)
    self.assertRaises(TypeError, str_tools.time_labels, 'hello world')

  def test_short_time_label(self):
    """
    Checks the short_time_label() function.
    """

    # test the pydoc examples
    self.assertEqual('01:51', str_tools.short_time_label(111))
    self.assertEqual('6-07:08:20', str_tools.short_time_label(544100))

    self.assertEqual('00:00', str_tools.short_time_label(0))

    self.assertRaises(TypeError, str_tools.short_time_label, None)
    self.assertRaises(TypeError, str_tools.short_time_label, 'hello world')
    self.assertRaises(ValueError, str_tools.short_time_label, -5)

  def test_parse_short_time_label(self):
    """
    Checks the parse_short_time_label() function.
    """

    # test the pydoc examples
    self.assertEqual(111, str_tools.parse_short_time_label('01:51'))
    self.assertEqual(544100, str_tools.parse_short_time_label('6-07:08:20'))

    self.assertEqual(110, str_tools.parse_short_time_label('01:50.62'))
    self.assertEqual(0, str_tools.parse_short_time_label('00:00'))

    # these aren't technically valid, but might as well allow unnecessary
    # digits to be dropped

    self.assertEqual(300, str_tools.parse_short_time_label('05:0'))
    self.assertEqual(300, str_tools.parse_short_time_label('5:00'))

    self.assertRaises(TypeError, str_tools.parse_short_time_label, None)
    self.assertRaises(TypeError, str_tools.parse_short_time_label, 100)

    self.assertRaises(ValueError, str_tools.parse_short_time_label, 'blarg')
    self.assertRaises(ValueError, str_tools.parse_short_time_label, '00')
    self.assertRaises(ValueError, str_tools.parse_short_time_label, '05:')
    self.assertRaises(ValueError, str_tools.parse_short_time_label, '05a:00')
    self.assertRaises(ValueError, str_tools.parse_short_time_label, '-05:00')

  def test_parse_iso_timestamp(self):
    """
    Checks the _parse_iso_timestamp() function.
    """

    test_inputs = {
      '2012-11-08T16:48:41.420251':
        datetime.datetime(2012, 11, 8, 16, 48, 41, 420251),
      '2012-11-08T16:48:41.000000':
        datetime.datetime(2012, 11, 8, 16, 48, 41, 0),
      '2012-11-08T16:48:41':
        datetime.datetime(2012, 11, 8, 16, 48, 41, 0),
    }

    for arg, expected in test_inputs.items():
      self.assertEqual(expected, str_tools._parse_iso_timestamp(arg))

    invalid_input = [
      None,
      32,
      'hello world',
      '2012-11-08T16:48:41.42025',    # too few microsecond digits
      '2012-11-08T16:48:41.4202511',  # too many microsecond digits
      '2012-11-08T16:48',
    ]

    for arg in invalid_input:
      self.assertRaises(ValueError, str_tools._parse_iso_timestamp, arg)
