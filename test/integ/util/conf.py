"""
Integration tests for the stem.util.conf class and functions.
"""

import os
import unittest

import stem.util.conf
import test.runner

CONF_HEADER = """# Demo configuration for integration tests to run against. Nothing to see here,
# move along, move along.
"""

EXAMPLE_CONF = """
destination.ip 1.2.3.4
destination.port blarg

startup.run export PATH=$PATH:~/bin
startup.run alias l=ls
"""

MULTILINE_CONF = """
multiline.entry.simple
|la de da
|and a ho hum

multiline.entry.leading_whitespace
 |la de da
     |and a ho hum

multiline.entry.empty

multiline.entry.squashed_top
|la de da
|and a ho hum
multiline.entry.squashed_bottom
|la de da
|and a ho hum
"""

HERALD_POEM = """
What a beautiful morning,
what a beautiful day.
Why are those arrows",
coming my way?!?"""


def _get_test_config_path():
  return test.runner.get_runner().get_test_dir('integ_test_cfg')


def _make_config(contents):
  """
  Writes a test configuration to disk, returning the path where it is located.
  """

  test_config_path = _get_test_config_path()

  test_conf_file = open(test_config_path, 'w')
  test_conf_file.write(CONF_HEADER)
  test_conf_file.write(contents)
  test_conf_file.close()

  return test_config_path


class TestConf(unittest.TestCase):
  def tearDown(self):
    # clears the config contents
    test_config = stem.util.conf.get_config('integ_testing')
    test_config.clear()
    test_config.clear_listeners()

    # cleans up test configurations we made
    test_config_path = _get_test_config_path()

    if os.path.exists(test_config_path):
      os.remove(test_config_path)

  def test_example(self):
    """
    Checks that the pydoc example is correct.
    """

    ssh_config = stem.util.conf.config_dict('integ_testing', {
      'login.user': 'atagar',
      'login.password': 'pepperjack_is_awesome!',
      'destination.ip': '127.0.0.1',
      'destination.port': 22,
      'startup.run': [],
    })

    test_config_path = _make_config(EXAMPLE_CONF)
    user_config = stem.util.conf.get_config('integ_testing')
    user_config.load(test_config_path)

    self.assertEqual('atagar', ssh_config['login.user'])
    self.assertEqual('pepperjack_is_awesome!', ssh_config['login.password'])
    self.assertEqual('1.2.3.4', ssh_config['destination.ip'])
    self.assertEqual(22, ssh_config['destination.port'])
    self.assertEqual(['export PATH=$PATH:~/bin', 'alias l=ls'], ssh_config['startup.run'])

  def test_load_multiline(self):
    """
    Tests the load method with multi-line configuration files.
    """

    test_config_path = _make_config(MULTILINE_CONF)
    test_config = stem.util.conf.get_config('integ_testing')
    test_config.load(test_config_path)

    for entry in ('simple', 'leading_whitespace', 'squashed_top', 'squashed_bottom'):
      self.assertEqual('la de da\nand a ho hum', test_config.get('multiline.entry.%s' % entry))

    self.assertEqual('', test_config.get('multiline.entry.empty'))

  def test_save(self):
    """
    Saves then reloads a configuration with several types of values.
    """

    # makes a configuration with a variety of types
    test_config = stem.util.conf.get_config('integ_testing')

    test_config.set('single_value', "yup, I'm there")
    test_config.set('multiple_values', 'a', False)
    test_config.set('multiple_values', 'b', False)
    test_config.set('multiple_values', 'c', False)
    test_config.set('multiline_value', HERALD_POEM)

    test_config.save(_get_test_config_path())
    test_config.clear()
    test_config.load()

    self.assertEqual("yup, I'm there", test_config.get_value('single_value'))
    self.assertEqual(['a', 'b', 'c'], test_config.get_value('multiple_values', multiple = True))
    self.assertEqual(HERALD_POEM, test_config.get_value('multiline_value'))
