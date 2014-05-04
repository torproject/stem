import unittest

from stem.interpretor.help import response, _normalize

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


CONTROLLER = Mock()

CONTROLLER.get_info.side_effect = lambda arg, _: {
  'info/names': GETINFO_NAMES,
  'config/names': GETCONF_NAMES,
  'events/names': 'BW DEBUG INFO NOTICE',
  'features/names': 'VERBOSE_NAMES EXTENDED_EVENTS',
}[arg]


class TestHelpResponses(unittest.TestCase):
  def test_normalization(self):
    self.assertEqual('', _normalize(''))
    self.assertEqual('', _normalize('   '))

    self.assertEqual('GETINFO', _normalize('GETINFO'))
    self.assertEqual('GETINFO', _normalize('GetInfo'))
    self.assertEqual('GETINFO', _normalize('getinfo'))
    self.assertEqual('GETINFO', _normalize('GETINFO version'))
    self.assertEqual('GETINFO', _normalize('GETINFO   '))

    self.assertEqual('INFO', _normalize('/info'))
    self.assertEqual('INFO', _normalize('/info caerSidi'))

  def test_unrecognized_option(self):
    result = response(CONTROLLER, 'FOOBAR')
    self.assertEqual("\x1b[1;31mNo help information available for 'FOOBAR'...\x1b[0m", result)

  def test_general_help(self):
    result = response(CONTROLLER, '')
    self.assertTrue('Interpretor commands include:' in result)
    self.assertTrue('\x1b[34;1m  GETINFO\x1b[0m\x1b[34m - queries information from tor\x1b[0m\n' in result)

  def test_getinfo_help(self):
    result = response(CONTROLLER, 'GETINFO')
    self.assertTrue('Queries the tor process for information. Options are...' in result)
    self.assertTrue('\x1b[34;1minfo/names                       \x1b[0m\x1b[34m - List of GETINFO options, types, and documentation.\n' in result)

  def test_getconf_help(self):
    result = response(CONTROLLER, 'GETCONF')
    self.assertTrue('Provides the current value for a given configuration value. Options include...' in result)
    self.assertTrue('\x1b[34mExitNodes                                 ExitPolicy\n' in result)

  def test_signal_help(self):
    result = response(CONTROLLER, 'SIGNAL')
    self.assertTrue('Issues a signal that tells the tor process to' in result)
    self.assertTrue('\x1b[34;1mRELOAD / HUP   \x1b[0m\x1b[34m - reload our torrc\n' in result)

  def test_setevents_help(self):
    result = response(CONTROLLER, 'SETEVENTS')
    self.assertTrue('Sets the events that we will receive.' in result)
    self.assertTrue('\x1b[34mBW                  DEBUG               INFO                NOTICE\n\x1b[0m' in result)

  def test_usefeature_help(self):
    result = response(CONTROLLER, 'USEFEATURE')
    self.assertTrue('Customizes the behavior of the control port.' in result)
    self.assertTrue('\x1b[34mVERBOSE_NAMES EXTENDED_EVENTS\n\x1b[0m' in result)
