"""
Unit tests for the stem.control module. The module's primarily exercised via
integ tests, but a few bits lend themselves to unit testing.
"""

import unittest

import stem.socket
import stem.version

from stem import InvalidArguments, InvalidRequest, ProtocolError
from stem.control import _parse_circ_path, Controller, EventType
from stem.response import events
from test import mocking

class TestControl(unittest.TestCase):
  def setUp(self):
    socket = stem.socket.ControlSocket()
    self.controller = Controller(socket, enable_caching = True)
  
  def tearDown(self):
    mocking.revert_mocking()
  
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
  
  def test_get_socks_listeners_old(self):
    """
    Exercises the get_socks_listeners() method as though talking to an old tor
    instance.
    """
    
    # An old tor raises stem.InvalidArguments for get_info about socks, but
    # get_socks_listeners should work anyway.
    
    mocking.mock_method(Controller, "get_info", mocking.raise_exception(InvalidArguments))
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "9050",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1"]
    }, is_method = True))
    self.assertEqual([('127.0.0.1', 9050)], self.controller.get_socks_listeners())
    
    # Again, an old tor, but SocksListenAddress overrides the port number.
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "9050",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1:1112"]
    }, is_method = True))
    self.assertEqual([('127.0.0.1', 1112)], self.controller.get_socks_listeners())
    
    # Again, an old tor, but multiple listeners
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "9050",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1:1112", "127.0.0.1:1114"]
    }, is_method = True))
    self.assertEqual([('127.0.0.1', 1112), ('127.0.0.1', 1114)], self.controller.get_socks_listeners())
    
    # Again, an old tor, but no SOCKS listeners
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "0",
      ("SocksListenAddress", "multiple=True"): []
    }, is_method = True))
    self.assertEqual([], self.controller.get_socks_listeners())
    
    # Where tor provides invalid ports or addresses
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "blarg",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1"]
    }, is_method = True))
    self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "0",
      ("SocksListenAddress", "multiple=True"): ["127.0.0.1:abc"]
    }, is_method = True))
    self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)
    
    mocking.mock_method(Controller, "get_conf", mocking.return_for_args({
      ("SocksPort",): "40",
      ("SocksListenAddress", "multiple=True"): ["500.0.0.1"]
    }, is_method = True))
    self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)
  
  def test_get_socks_listeners_new(self):
    """
    Exercises the get_socks_listeners() method as if talking to a newer tor
    instance.
    """
    
    # multiple SOCKS listeners
    mocking.mock_method(Controller, "get_info", mocking.return_value(
      '"127.0.0.1:1112" "127.0.0.1:1114"'
    ))
    self.assertEqual([('127.0.0.1', 1112), ('127.0.0.1', 1114)],
        self.controller.get_socks_listeners())
    
    # no SOCKS listeners
    mocking.mock_method(Controller, "get_info", mocking.return_value(""))
    self.assertEqual([], self.controller.get_socks_listeners())
    
    # check where GETINFO provides malformed content
    
    invalid_responses = (
      '"127.0.0.1"',        # address only
      '"1112"',             # port only
      '"5127.0.0.1:1112"',  # invlaid address
      '"127.0.0.1:991112"', # invalid port
    )
    
    for response in invalid_responses:
      mocking.mock_method(Controller, "get_info", mocking.return_value(response))
      self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)
  
  def test_get_streams(self):
    """
    Exercises the get_streams() method.
    """
    
    # get a list of fake, but good looking, streams
    valid_streams = (
      ("1", "NEW", "4", "10.10.10.1:80"),
      ("2", "SUCCEEDED", "4", "10.10.10.1:80"),
      ("3", "SUCCEEDED", "4", "10.10.10.1:80")
    )
    
    responses = ["%s\r\n" % " ".join(entry) for entry in valid_streams]
    
    mocking.mock_method(Controller, "get_info", mocking.return_value(
      "".join(responses)
    ))
    
    streams = self.controller.get_streams()
    self.assertEqual(len(valid_streams), len(streams))
    
    for index, stream in enumerate(streams):
      self.assertEqual(valid_streams[index][0], stream.id)
      self.assertEqual(valid_streams[index][1], stream.status)
      self.assertEqual(valid_streams[index][2], stream.circ_id)
      self.assertEqual(valid_streams[index][3], stream.target)
  
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

