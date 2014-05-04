import unittest

import stem.response

from stem.interpretor.commands import ControlInterpretor

from test import mocking
from test.unit.interpretor import CONTROLLER

EXPECTED_EVENTS_RESPONSE = """\
\x1b[34mBW 15 25\x1b[0m
\x1b[34mBW 758 570\x1b[0m
\x1b[34mDEBUG connection_edge_process_relay_cell(): Got an extended cell! Yay.\x1b[0m
"""


class TestInterpretorCommands(unittest.TestCase):
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
