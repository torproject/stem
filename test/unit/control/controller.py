"""
Unit tests for the stem.control module. The module's primarily exercised via
integ tests, but a few bits lend themselves to unit testing.
"""

import unittest

import stem.socket
import stem.version

from stem import InvalidRequest, ProtocolError
from stem.control import _parse_circ_path, Controller, EventType
from test import mocking

class TestControl(unittest.TestCase):
  def setUp(self):
    socket = stem.socket.ControlSocket()
    self.controller = Controller(socket)
  
  def tearDown(self):
    mocking.revert_mocking()
  
  def test_parse_circ_path(self):
    """
    Exercises the _parse_circ_path() helper function.
    """
    
    # empty input
    
    self.assertEqual([], _parse_circ_path(None))
    self.assertEqual([], _parse_circ_path(''))
    
    # check the pydoc examples
    
    pydoc_examples = {
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz':
        [('999A226EBED397F331B612FE1E4CFAE5C1F201BA', 'piyaz')],
      '$E57A476CD4DFBD99B4EE52A100A58610AD6E80B9,hamburgerphone,PrivacyRepublic14':
        [('E57A476CD4DFBD99B4EE52A100A58610AD6E80B9', None),
         (None, 'hamburgerphone'),
         (None, 'PrivacyRepublic14'),
        ],
    }
    
    for test_input, expected in pydoc_examples.items():
      self.assertEqual(expected, _parse_circ_path(test_input))
    
    # exercise with some invalid inputs
    
    malformed_inputs = [
      '=piyaz', # no fingerprint
      '999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz', # fingerprint missing prefix
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BAA=piyaz', # fingerprint too long
      '$999A226EBED397F331B612FE1E4CFAE5C1F201B=piyaz', # fingerprint too short
      '$999A226EBED397F331B612FE1E4CFAE5C1F201Bz=piyaz', # invalid character in fingerprint
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BA=', # no nickname
    ]
    
    for test_input in malformed_inputs:
      self.assertRaises(ProtocolError, _parse_circ_path, test_input)
  
  def test_event_listening(self):
    """
    Exercises the add_event_listener and remove_event_listener methods.
    """
    
    # set up for failure to create any events
    mocking.mock_method(Controller, "get_version", mocking.return_value(stem.version.Version('0.1.0.14')))
    self.assertRaises(InvalidRequest, self.controller.add_event_listener, mocking.no_op(), EventType.BW)
    
    # set up to only fail newer events
    mocking.mock_method(Controller, "get_version", mocking.return_value(stem.version.Version('0.2.0.35')))
    
    # EventType.BW is one of the earliest events
    self.controller.add_event_listener(mocking.no_op(), EventType.BW)
    
    # EventType.SIGNAL was added in tor version 0.2.3.1-alpha
    self.assertRaises(InvalidRequest, self.controller.add_event_listener, mocking.no_op(), EventType.SIGNAL)

