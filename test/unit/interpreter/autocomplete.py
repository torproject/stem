import unittest

from stem.interpreter.autocomplete import _get_commands, Autocompleter

from test.unit.interpreter import CONTROLLER

try:
  # added in python 3.3
  from unittest.mock import Mock
except ImportError:
  from mock import Mock


class TestAutocompletion(unittest.TestCase):
  def test_autocomplete_results_from_config(self):
    """
    Check that we load autocompletion results from our configuration.
    """

    commands = _get_commands(None)
    self.assertTrue('PROTOCOLINFO' in commands)
    self.assertTrue('/quit' in commands)

  def test_autocomplete_results_from_tor(self):
    """
    Check our ability to determine autocompletion results based on our tor
    instance's capabilities.
    """

    # Check that when GETINFO requests fail we have base commands, but nothing
    # with arguments.

    controller = Mock()
    controller.get_info.return_value = None
    commands = _get_commands(controller)

    self.assertTrue('GETINFO ' in commands)
    self.assertTrue('GETCONF ' in commands)
    self.assertTrue('SIGNAL ' in commands)

    self.assertFalse('GETINFO info/names' in commands)
    self.assertFalse('GETCONF ExitPolicy' in commands)
    self.assertFalse('SIGNAL SHUTDOWN' in commands)

    # Now check where we should be able to determine tor's capabilities.

    commands = _get_commands(CONTROLLER)

    expected = (
      'GETINFO info/names',
      'GETINFO ip-to-country/',
      'GETINFO md/id/',

      'GETCONF ExitNodes',
      'GETCONF ExitPolicy',
      'SETCONF ExitPolicy',
      'RESETCONF ExitPolicy',

      'SETEVENTS BW',
      'SETEVENTS INFO',
      'USEFEATURE VERBOSE_NAMES',
      'USEFEATURE EXTENDED_EVENTS',
      'SIGNAL RELOAD',
      'SIGNAL SHUTDOWN',
    )

    for result in expected:
      self.assertTrue(result in commands)

    # We shouldn't include the base commands since we have results with
    # their arguments.

    self.assertFalse('GETINFO ' in commands)
    self.assertFalse('GETCONF ' in commands)
    self.assertFalse('SIGNAL ' in commands)

  def test_autocompleter_match(self):
    """
    Exercise our Autocompleter's match method.
    """

    autocompleter = Autocompleter(None)

    self.assertEqual(['/help'], autocompleter.matches('/help'))
    self.assertEqual(['/help'], autocompleter.matches('/hel'))
    self.assertEqual(['/help'], autocompleter.matches('/he'))
    self.assertEqual(['/help'], autocompleter.matches('/h'))
    self.assertEqual(['/help', '/events', '/info', '/quit'], autocompleter.matches('/'))

    # check case sensitivity

    self.assertEqual(['/help'], autocompleter.matches('/HELP'))
    self.assertEqual(['/help'], autocompleter.matches('/HeLp'))

    # check when we shouldn't have any matches

    self.assertEqual([], autocompleter.matches('blarg'))

  def test_autocompleter_complete(self):
    """
    Exercise our Autocompleter's complete method.
    """

    autocompleter = Autocompleter(None)

    self.assertEqual('/help', autocompleter.complete('/', 0))
    self.assertEqual('/events', autocompleter.complete('/', 1))
    self.assertEqual('/info', autocompleter.complete('/', 2))
    self.assertEqual('/quit', autocompleter.complete('/', 3))
    self.assertEqual(None, autocompleter.complete('/', 4))

    self.assertEqual(None, autocompleter.complete('blarg', 0))
