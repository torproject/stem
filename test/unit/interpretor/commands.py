import unittest

import stem
import stem.response

from stem.interpretor.commands import ControlInterpretor, _get_fingerprint

from test import mocking
from test.unit.interpretor import CONTROLLER

try:
  # added in python 3.3
  from unittest.mock import Mock
except ImportError:
  from mock import Mock

EXPECTED_EVENTS_RESPONSE = """\
\x1b[34mBW 15 25\x1b[0m
\x1b[34mBW 758 570\x1b[0m
\x1b[34mDEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.\x1b[0m
"""

FINGERPRINT = '9695DFC35FFEB861329B9F1AB04C46397020CE31'


class TestInterpretorCommands(unittest.TestCase):
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

  def test_quit(self):
    interpretor = ControlInterpretor(CONTROLLER)
    self.assertRaises(stem.SocketClosed, interpretor.run_command, '/quit')

  def test_help(self):
    interpretor = ControlInterpretor(CONTROLLER)

    self.assertTrue('Interpretor commands include:' in interpretor.run_command('/help'))
    self.assertTrue('Queries the tor process for information.' in interpretor.run_command('/help GETINFO'))
    self.assertTrue('Queries the tor process for information.' in interpretor.run_command('/help GETINFO version'))

  def test_events(self):
    interpretor = ControlInterpretor(CONTROLLER)

    # no received events

    self.assertEqual('\n', interpretor.run_command('/events'))

    # with enqueued events

    event_contents = (
      '650 BW 15 25',
      '650 BW 758 570',
      '650 DEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.',
    )

    for content in event_contents:
      event = mocking.get_message(content)
      stem.response.convert('EVENT', event)
      interpretor.register_event(event)

    self.assertEqual(EXPECTED_EVENTS_RESPONSE, interpretor.run_command('/events'))
