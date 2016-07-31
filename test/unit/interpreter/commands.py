import datetime
import unittest

import stem
import stem.response
import stem.version

from stem.interpreter.commands import ControlInterpreter, _get_fingerprint

from test import mocking
from test.unit.interpreter import CONTROLLER

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

EXPECTED_EVENTS_RESPONSE = """\
\x1b[34mBW 15 25\x1b[0m
\x1b[34mBW 758 570\x1b[0m
\x1b[34mDEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.\x1b[0m
"""

EXPECTED_INFO_RESPONSE = """\
moria1 (9695DFC35FFEB861329B9F1AB04C46397020CE31)
\x1b[34;1maddress: \x1b[0m128.31.0.34:9101 (moria.csail.mit.edu)
\x1b[34;1mtor version: \x1b[0m0.2.5.4-alpha-dev
\x1b[34;1mflags: \x1b[0mAuthority, Fast, Guard, HSDir, Named, Running, Stable, V2Dir, Valid
\x1b[34;1mexit policy: \x1b[0mreject *:*
\x1b[34;1mcontact: \x1b[0m1024D/28988BF5 arma mit edu
"""

EXPECTED_GETCONF_RESPONSE = """\
\x1b[34;1mlog\x1b[0m\x1b[34m => notice stdout\x1b[0m
\x1b[34;1maddress\x1b[0m\x1b[34m => \x1b[0m

"""

FINGERPRINT = '9695DFC35FFEB861329B9F1AB04C46397020CE31'


class TestInterpreterCommands(unittest.TestCase):
  def test_get_fingerprint_for_ourselves(self):
    controller = Mock()

    controller.get_info.side_effect = lambda arg: {
      'fingerprint': FINGERPRINT,
    }[arg]

    self.assertEqual(FINGERPRINT, _get_fingerprint('', controller))

    controller.get_info.side_effect = stem.ControllerError
    self.assertRaises(ValueError, _get_fingerprint, '', controller)

  def test_get_fingerprint_for_fingerprint(self):
    self.assertEqual(FINGERPRINT, _get_fingerprint(FINGERPRINT, Mock()))

  def test_get_fingerprint_for_nickname(self):
    controller, descriptor = Mock(), Mock()
    descriptor.fingerprint = FINGERPRINT

    controller.get_network_status.side_effect = lambda arg: {
      'moria1': descriptor,
    }[arg]

    self.assertEqual(FINGERPRINT, _get_fingerprint('moria1', controller))

    controller.get_network_status.side_effect = stem.ControllerError
    self.assertRaises(ValueError, _get_fingerprint, 'moria1', controller)

  def test_get_fingerprint_for_address(self):
    controller = Mock()

    self.assertRaises(ValueError, _get_fingerprint, '127.0.0.1:-1', controller)
    self.assertRaises(ValueError, _get_fingerprint, '127.0.0.901:80', controller)

    descriptor = Mock()
    descriptor.address = '127.0.0.1'
    descriptor.or_port = 80
    descriptor.fingerprint = FINGERPRINT

    controller.get_network_statuses.return_value = [descriptor]

    self.assertEqual(FINGERPRINT, _get_fingerprint('127.0.0.1', controller))
    self.assertEqual(FINGERPRINT, _get_fingerprint('127.0.0.1:80', controller))
    self.assertRaises(ValueError, _get_fingerprint, '127.0.0.1:81', controller)
    self.assertRaises(ValueError, _get_fingerprint, '127.0.0.2', controller)

  def test_get_fingerprint_for_unrecognized_inputs(self):
    self.assertRaises(ValueError, _get_fingerprint, 'blarg!', Mock())

  def test_when_disconnected(self):
    controller = Mock()
    controller.is_alive.return_value = False

    interpreter = ControlInterpreter(controller)
    self.assertRaises(stem.SocketClosed, interpreter.run_command, '/help')

  def test_quit(self):
    interpreter = ControlInterpreter(CONTROLLER)
    self.assertRaises(stem.SocketClosed, interpreter.run_command, '/quit')
    self.assertRaises(stem.SocketClosed, interpreter.run_command, 'QUIT')

  def test_help(self):
    interpreter = ControlInterpreter(CONTROLLER)

    self.assertTrue('Interpreter commands include:' in interpreter.run_command('/help'))
    self.assertTrue('Queries the tor process for information.' in interpreter.run_command('/help GETINFO'))
    self.assertTrue('Queries the tor process for information.' in interpreter.run_command('/help GETINFO version'))

  def test_events(self):
    interpreter = ControlInterpreter(CONTROLLER)

    # no received events

    self.assertEqual('\n', interpreter.run_command('/events'))

    # with enqueued events

    event_contents = (
      '650 BW 15 25',
      '650 BW 758 570',
      '650 DEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.',
    )

    for content in event_contents:
      event = mocking.get_message(content)
      stem.response.convert('EVENT', event)
      interpreter._received_events.append(event)

    self.assertEqual(EXPECTED_EVENTS_RESPONSE, interpreter.run_command('/events'))

  @patch('stem.descriptor.remote.DescriptorDownloader')
  @patch('socket.gethostbyaddr', Mock(return_value = ['moria.csail.mit.edu']))
  def test_info(self, downloader_mock):
    controller, server_desc, ns_desc = Mock(), Mock(), Mock()

    controller.get_microdescriptor.return_value = None
    controller.get_server_descriptor.return_value = server_desc
    controller.get_network_status.return_value = ns_desc

    downloader_mock().get_server_descriptors.return_value = [server_desc]

    controller.get_info.side_effect = lambda arg, _: {
      'ip-to-country/128.31.0.34': 'us',
    }[arg]

    ns_desc.address = '128.31.0.34'
    ns_desc.or_port = 9101
    ns_desc.published = datetime.datetime(2014, 5, 5, 5, 52, 5)
    ns_desc.nickname = 'moria1'
    ns_desc.flags = ['Authority', 'Fast', 'Guard', 'HSDir', 'Named', 'Running', 'Stable', 'V2Dir', 'Valid']

    server_desc.exit_policy = 'reject *:*'
    server_desc.platform = 'Linux'
    server_desc.tor_version = stem.version.Version('0.2.5.4-alpha-dev')
    server_desc.contact = '1024D/28988BF5 arma mit edu'

    interpreter = ControlInterpreter(controller)
    self.assertTrue(interpreter.run_command('/info ' + FINGERPRINT).startswith(EXPECTED_INFO_RESPONSE))

  def test_unrecognized_interpreter_command(self):
    interpreter = ControlInterpreter(CONTROLLER)

    expected = "\x1b[1;31m'/unrecognized' isn't a recognized command\x1b[0m\n"
    self.assertEqual(expected, interpreter.run_command('/unrecognized'))

  def test_getinfo(self):
    response = '250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)\r\n250 OK'

    controller = Mock()
    controller.msg.return_value = mocking.get_message(response)

    interpreter = ControlInterpreter(controller)

    self.assertEqual('\x1b[34m250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)\r\x1b[0m\n\x1b[34m250 OK\x1b[0m\n', interpreter.run_command('GETINFO version'))
    self.assertEqual('\x1b[34m250-version=0.2.5.1-alpha-dev (git-245ecfff36c0cecc)\r\x1b[0m\n\x1b[34m250 OK\x1b[0m\n', interpreter.run_command('GETINFO version'))
    controller.msg.assert_called_with('GETINFO version')

    controller.msg.side_effect = stem.ControllerError('kaboom!')
    self.assertEqual('\x1b[1;31mkaboom!\x1b[0m\n', interpreter.run_command('getinfo process/user'))

  def test_getconf(self):
    response = '250-Log=notice stdout\r\n250 Address'

    controller = Mock()
    controller.msg.return_value = mocking.get_message(response)

    interpreter = ControlInterpreter(controller)

    self.assertEqual('\x1b[34m250-Log=notice stdout\r\x1b[0m\n\x1b[34m250 Address\x1b[0m\n', interpreter.run_command('GETCONF log address'))
    controller.msg.assert_called_with('GETCONF log address')

  def test_setevents(self):
    controller = Mock()
    controller.msg.return_value = mocking.get_message('250 OK')

    interpreter = ControlInterpreter(controller)

    self.assertEqual('\x1b[34m250 OK\x1b[0m\n', interpreter.run_command('SETEVENTS BW'))
