"""
Unit tests for the stem.control module. The module's primarily exercised via
integ tests, but a few bits lend themselves to unit testing.
"""

import unittest

import stem.descriptor.router_status_entry
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
  
  def test_get_version(self):
    """
    Exercises the get_version() method.
    """
    
    try:
      # Use one version for first check.
      version_2_1 = "0.2.1.32"
      version_2_1_object = stem.version.Version(version_2_1)
      mocking.mock_method(Controller, "get_info", mocking.return_value(version_2_1))
      
      # Return a version with a cold cache.
      self.assertEqual(version_2_1_object, self.controller.get_version())
      
      # Use a different version for second check.
      version_2_2 = "0.2.2.39"
      version_2_2_object = stem.version.Version(version_2_2)
      mocking.mock_method(Controller, "get_info", mocking.return_value(version_2_2))
      
      # Return a version with a hot cache, so it will be the old version.
      self.assertEqual(version_2_1_object, self.controller.get_version())
      
      # Turn off caching.
      self.controller._is_caching_enabled = False
      # Return a version without caching, so it will be the new version.
      self.assertEqual(version_2_2_object, self.controller.get_version())
      
      # Raise an exception in the get_info() call.
      mocking.mock_method(Controller, "get_info", mocking.raise_exception(InvalidArguments))
      
      # Get a default value when the call fails.
      self.assertEqual(
        "default returned",
        self.controller.get_version(default = "default returned")
      )
      
      # No default value, accept the error.
      self.assertRaises(InvalidArguments, self.controller.get_version)
      
      # Give a bad version.  The stem.version.Version ValueError should bubble up.
      version_A_42 = "0.A.42.spam"
      mocking.mock_method(Controller, "get_info", mocking.return_value(version_A_42))
      self.assertRaises(ValueError, self.controller.get_version)
    finally:
      # Turn caching back on before we leave.
      self.controller._is_caching_enabled = True
  
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
    
    self.assertEqual(
      [('127.0.0.1', 1112), ('127.0.0.1', 1114)],
      self.controller.get_socks_listeners()
    )
    
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
  
  def test_get_protocolinfo(self):
    """
    Exercises the get_protocolinfo() method.
    """
    
    # Use the handy mocked protocolinfo response.
    mocking.mock(stem.connection.get_protocolinfo, mocking.return_value(
      mocking.get_protocolinfo_response()
    ))
    # Compare the str representation of these object, because the class
    # does not have, nor need, a direct comparison operator.
    self.assertEqual(str(mocking.get_protocolinfo_response()), str(self.controller.get_protocolinfo()))
    
    # Raise an exception in the stem.connection.get_protocolinfo() call.
    mocking.mock(stem.connection.get_protocolinfo, mocking.raise_exception(ProtocolError))
    
    # Get a default value when the call fails.
    
    self.assertEqual(
      "default returned",
      self.controller.get_protocolinfo(default = "default returned")
    )
    
    # No default value, accept the error.
    self.assertRaises(ProtocolError, self.controller.get_protocolinfo)
  
  def test_get_network_status(self):
    """
    Exercises the get_network_status() method.
    """
    
    # Build a single router status entry.
    nickname = "Beaver"
    fingerprint = "/96bKo4soysolMgKn5Hex2nyFSY"
    desc = "r %s %s u5lTXJKGsLKufRLnSyVqT7TdGYw 2012-12-30 22:02:49 77.223.43.54 9001 0\ns Fast Named Running Stable Valid\nw Bandwidth=75" % (nickname, fingerprint)
    router = stem.descriptor.router_status_entry.RouterStatusEntryV2(desc)
    
    # Always return the same router status entry.
    mocking.mock_method(Controller, "get_info", mocking.return_value(desc))
    
    # Pretend to get the router status entry with its name.
    self.assertEqual(router, self.controller.get_network_status(nickname))
    
    # Pretend to get the router status entry with its fingerprint.
    hex_fingerprint = stem.descriptor.router_status_entry._decode_fingerprint(fingerprint, False)
    self.assertEqual(router, self.controller.get_network_status(hex_fingerprint))
    
    # Mangle hex fingerprint and try again.
    hex_fingerprint = hex_fingerprint[2:]
    self.assertRaises(ValueError, self.controller.get_network_status, hex_fingerprint)
    
    # Raise an exception in the get_info() call.
    mocking.mock_method(Controller, "get_info", mocking.raise_exception(InvalidArguments))
    
    # Get a default value when the call fails.
    
    self.assertEqual(
      "default returned",
      self.controller.get_network_status(nickname, default = "default returned")
    )
    
    # No default value, accept the error.
    self.assertRaises(InvalidArguments, self.controller.get_network_status, nickname)
  
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
        [
          ('E57A476CD4DFBD99B4EE52A100A58610AD6E80B9', None),
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

