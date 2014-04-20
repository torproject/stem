import unittest

from stem.interpretor.autocomplete import _get_commands, Autocompleter

try:
  # added in python 3.3
  from unittest.mock import Mock
except ImportError:
  from mock import Mock

GETINFO_NAMES = """
info/names -- List of GETINFO options, types, and documentation.
ip-to-country/* -- Perform a GEOIP lookup
md/id/* -- Microdescriptors by ID
""".strip()

GETCONF_NAMES = """
ExitNodes RouterList
ExitPolicy LineList
ExitPolicyRejectPrivate Boolean
""".strip()


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

    controller.get_info.side_effect = lambda arg, _: {
      'info/names': GETINFO_NAMES,
      'config/names': GETCONF_NAMES,
      'events/names': 'BW DEBUG INFO NOTICE',
      'features/names': 'VERBOSE_NAMES EXTENDED_EVENTS',
      'signal/names': 'RELOAD HUP SHUTDOWN',
    }[arg]

    commands = _get_commands(controller)

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
