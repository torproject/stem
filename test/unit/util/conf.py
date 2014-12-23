"""
Unit tests for the stem.util.conf class and functions.
"""

import unittest

import stem.util.conf
import stem.util.enum

from stem.util.conf import parse_enum, parse_enum_csv


class TestConf(unittest.TestCase):
  def tearDown(self):
    # clears the config contents
    test_config = stem.util.conf.get_config('unit_testing')
    test_config.clear()
    test_config.clear_listeners()

  def test_config_dict(self):
    """
    Tests the config_dict function.
    """

    my_config = {
      'bool_value': False,
      'int_value': 5,
      'str_value': 'hello',
      'list_value': [],
    }

    test_config = stem.util.conf.get_config('unit_testing')

    # checks that sync causes existing contents to be applied
    test_config.set('bool_value', 'true')
    my_config = stem.util.conf.config_dict('unit_testing', my_config)
    self.assertEqual(True, my_config['bool_value'])

    # check a basic synchronize
    test_config.set('str_value', 'me')
    self.assertEqual('me', my_config['str_value'])

    # synchronize with a type mismatch, should keep the old value
    test_config.set('int_value', '7a')
    self.assertEqual(5, my_config['int_value'])

    # changes for a collection
    test_config.set('list_value', 'a', False)
    self.assertEqual(['a'], my_config['list_value'])

    test_config.set('list_value', 'b', False)
    self.assertEqual(['a', 'b'], my_config['list_value'])

    test_config.set('list_value', 'c', False)
    self.assertEqual(['a', 'b', 'c'], my_config['list_value'])

  def test_parse_enum(self):
    """
    Tests the parse_enum function.
    """

    Insects = stem.util.enum.Enum('BUTTERFLY', 'LADYBUG', 'CRICKET')
    self.assertEqual(Insects.LADYBUG, parse_enum('my_option', 'ladybug', Insects))
    self.assertRaises(ValueError, parse_enum, 'my_option', 'ugabuga', Insects)
    self.assertRaises(ValueError, parse_enum, 'my_option', 'ladybug, cricket', Insects)

  def test_parse_enum_csv(self):
    """
    Tests the parse_enum_csv function.
    """

    Insects = stem.util.enum.Enum('BUTTERFLY', 'LADYBUG', 'CRICKET')

    # check the case insensitivity

    self.assertEqual([Insects.LADYBUG], parse_enum_csv('my_option', 'ladybug', Insects))
    self.assertEqual([Insects.LADYBUG], parse_enum_csv('my_option', 'Ladybug', Insects))
    self.assertEqual([Insects.LADYBUG], parse_enum_csv('my_option', 'LaDyBuG', Insects))
    self.assertEqual([Insects.LADYBUG], parse_enum_csv('my_option', 'LADYBUG', Insects))

    # various number of values

    self.assertEqual([], parse_enum_csv('my_option', '', Insects))
    self.assertEqual([Insects.LADYBUG], parse_enum_csv('my_option', 'ladybug', Insects))

    self.assertEqual(
      [Insects.LADYBUG, Insects.BUTTERFLY],
      parse_enum_csv('my_option', 'ladybug, butterfly', Insects)
    )

    self.assertEqual(
      [Insects.LADYBUG, Insects.BUTTERFLY, Insects.CRICKET],
      parse_enum_csv('my_option', 'ladybug, butterfly, cricket', Insects)
    )

    # edge cases for count argument where things are ok

    self.assertEqual(
      [Insects.LADYBUG, Insects.BUTTERFLY],
      parse_enum_csv('my_option', 'ladybug, butterfly', Insects, 2)
    )

    self.assertEqual(
      [Insects.LADYBUG, Insects.BUTTERFLY],
      parse_enum_csv('my_option', 'ladybug, butterfly', Insects, (1, 2))
    )

    self.assertEqual(
      [Insects.LADYBUG, Insects.BUTTERFLY],
      parse_enum_csv('my_option', 'ladybug, butterfly', Insects, (2, 3))
    )

    self.assertEqual(
      [Insects.LADYBUG, Insects.BUTTERFLY],
      parse_enum_csv('my_option', 'ladybug, butterfly', Insects, (2, 2))
    )

    # failure cases

    self.assertRaises(ValueError, parse_enum_csv, 'my_option', 'ugabuga', Insects)
    self.assertRaises(ValueError, parse_enum_csv, 'my_option', 'ladybug, ugabuga', Insects)
    self.assertRaises(ValueError, parse_enum_csv, 'my_option', 'ladybug butterfly', Insects)  # no comma
    self.assertRaises(ValueError, parse_enum_csv, 'my_option', 'ladybug', Insects, 2)
    self.assertRaises(ValueError, parse_enum_csv, 'my_option', 'ladybug', Insects, (2, 3))

  def test_clear(self):
    """
    Tests the clear method.
    """

    test_config = stem.util.conf.get_config('unit_testing')
    self.assertEqual([], list(test_config.keys()))

    # tests clearing when we're already empty
    test_config.clear()
    self.assertEqual([], list(test_config.keys()))

    # tests clearing when we have contents
    test_config.set('hello', 'world')
    self.assertEqual(['hello'], list(test_config.keys()))

    test_config.clear()
    self.assertEqual([], list(test_config.keys()))

  def test_listeners(self):
    """
    Tests the add_listener and clear_listeners methods.
    """

    listener_received_keys = []

    def test_listener(config, key):
      self.assertEqual(config, stem.util.conf.get_config('unit_testing'))
      listener_received_keys.append(key)

    test_config = stem.util.conf.get_config('unit_testing')
    test_config.add_listener(test_listener)

    self.assertEqual([], listener_received_keys)
    test_config.set('hello', 'world')
    self.assertEqual(['hello'], listener_received_keys)

    test_config.clear_listeners()

    test_config.set('foo', 'bar')
    self.assertEqual(['hello'], listener_received_keys)

  def test_unused_keys(self):
    """
    Tests the unused_keys method.
    """

    test_config = stem.util.conf.get_config('unit_testing')
    test_config.set('hello', 'world')
    test_config.set('foo', 'bar')
    test_config.set('pw', '12345')

    test_config.get('hello')
    test_config.get_value('foo')

    self.assertEqual(set(['pw']), test_config.unused_keys())

    test_config.get('pw')
    self.assertEqual(set(), test_config.unused_keys())

  def test_get(self):
    """
    Tests the get and get_value methods.
    """

    test_config = stem.util.conf.get_config('unit_testing')
    test_config.set('bool_value', 'true')
    test_config.set('int_value', '11')
    test_config.set('float_value', '11.1')
    test_config.set('str_value', 'world')
    test_config.set('list_value', 'a', False)
    test_config.set('list_value', 'b', False)
    test_config.set('list_value', 'c', False)
    test_config.set('map_value', 'foo => bar')

    # check that we get the default for type mismatch or missing values

    self.assertEqual(5, test_config.get('foo', 5))
    self.assertEqual(5, test_config.get('bool_value', 5))

    # checks that we get a string when no default is supplied

    self.assertEqual('11', test_config.get('int_value'))

    # exercise type casting for each of the supported types

    self.assertEqual(True, test_config.get('bool_value', False))
    self.assertEqual(11, test_config.get('int_value', 0))
    self.assertEqual(11.1, test_config.get('float_value', 0.0))
    self.assertEqual('world', test_config.get('str_value', ''))
    self.assertEqual(['a', 'b', 'c'], test_config.get('list_value', []))
    self.assertEqual(('a', 'b', 'c'), test_config.get('list_value', ()))
    self.assertEqual({'foo': 'bar'}, test_config.get('map_value', {}))

    # the get_value is similar, though only provides back a string or list

    self.assertEqual('c', test_config.get_value('list_value'))
    self.assertEqual(['a', 'b', 'c'], test_config.get_value('list_value', multiple = True))

    self.assertEqual(None, test_config.get_value('foo'))
    self.assertEqual('hello', test_config.get_value('foo', 'hello'))
