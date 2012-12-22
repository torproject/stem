"""
Unit tests for the stem.control module. The module's primarily exercised via
integ tests, but a few bits lend themselves to unit testing.
"""

import unittest

import stem.socket
import stem.version

from stem import InvalidArguments, InvalidRequest, ProtocolError
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
  
  def test_socks_port_old_tor(self):
    """
    Exercises the get_socks_ports method as if talking to an old tor process.
    """
    
    # An old tor raises stem.InvalidArguments for get_info about socks, but
    #  get_socks_ports returns the socks information, anyway.
    mocking.mock_method(Controller, "get_info", mocking.raise_exception(InvalidArguments))
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "9050",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1"]
    }, method = True))
    self.assertEqual([('127.0.0.1', 9050)], self.controller.get_socks_ports())
    
    # Again, an old tor, but SocksListenAddress overrides the port number.
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "9050",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1:1112"]
    }, method = True))
    self.assertEqual([('127.0.0.1', 1112)], self.controller.get_socks_ports())
    
    # Again, an old tor, but multiple listeners
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "9050",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1:1112", "127.0.0.1:1114"]
    }, method = True))
    self.assertEqual([('127.0.0.1', 1112), ('127.0.0.1', 1114)], self.controller.get_socks_ports())
    
    # Again, an old tor, but no SOCKS listeners
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "0",
      ("SocksListenAddress", "multiple=True"): []
    }, method = True))
    self.assertEqual([], self.controller.get_socks_ports())
  
  def test_socks_port_new_tor(self):
    """
    Exercises the get_socks_ports method as if talking to a newer tor process.
    """
    
    # multiple SOCKS listeners
    mocking.mock_method(Controller, "get_info", mocking.return_value(
      "\"127.0.0.1:1112\" \"127.0.0.1:1114\""
    ))
    self.assertEqual([('127.0.0.1', 1112), ('127.0.0.1', 1114)],
        self.controller.get_socks_ports())
    
    # no SOCKS listeners
    mocking.mock_method(Controller, "get_info", mocking.return_value(""))
    self.assertEqual([], self.controller.get_socks_ports())

