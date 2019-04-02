"""
Unit tests for the stem.control module. The module's primarily exercised via
integ tests, but a few bits lend themselves to unit testing.
"""

import datetime
import io
import unittest

import stem.descriptor.router_status_entry
import stem.response
import stem.response.events
import stem.socket
import stem.util.system
import stem.version

from stem import ControllerError, DescriptorUnavailable, InvalidArguments, InvalidRequest, ProtocolError, UnsatisfiableRequest
from stem.control import MALFORMED_EVENTS, _parse_circ_path, Listener, Controller, EventType
from stem.response import ControlMessage
from stem.exit_policy import ExitPolicy

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

NS_DESC = 'r %s %s u5lTXJKGsLKufRLnSyVqT7TdGYw 2012-12-30 22:02:49 77.223.43.54 9001 0\ns Fast Named Running Stable Valid\nw Bandwidth=75'
TEST_TIMESTAMP = 12345

BW_EVENT = ControlMessage.from_str('650 BW 15 25', 'EVENT', normalize = True, arrived_at = TEST_TIMESTAMP)
CIRC_EVENT = ControlMessage.from_str('650 CIRC 4 LAUNCHED', 'EVENT', normalize = True, arrived_at = TEST_TIMESTAMP)
BAD_EVENT = ControlMessage.from_str('650 BW &15* 25', normalize = True, arrived_at = TEST_TIMESTAMP)


class TestControl(unittest.TestCase):
  def setUp(self):
    socket = stem.socket.ControlSocket()

    # When initially constructing a controller we need to suppress msg, so our
    # constructor's SETEVENTS requests pass.

    with patch('stem.control.BaseController.msg', Mock()):
      self.controller = Controller(socket)

      self.circ_listener = Mock()
      self.controller.add_event_listener(self.circ_listener, EventType.CIRC)

      self.bw_listener = Mock()
      self.controller.add_event_listener(self.bw_listener, EventType.BW)

      self.malformed_listener = Mock()
      self.controller.add_event_listener(self.malformed_listener, MALFORMED_EVENTS)

  def test_event_description(self):
    self.assertEqual("Logging at the debug runlevel. This is low level, high volume information about tor's internals that generally isn't useful to users.", stem.control.event_description('DEBUG'))
    self.assertEqual('Event emitted every second with the bytes sent and received by tor.', stem.control.event_description('BW'))
    self.assertEqual('Event emitted every second with the bytes sent and received by tor.', stem.control.event_description('bw'))

  def test_event_description_includes_all_events(self):
    self.assertEqual(None, stem.control.event_description('NO_SUCH_EVENT'))

    for event in stem.control.EventType:
      self.assertTrue(stem.control.event_description(event) is not None)

  @patch('stem.control.Controller.msg')
  def test_get_info(self, msg_mock):
    msg_mock.return_value = ControlMessage.from_str('250-hello=hi right back!\r\n250 OK\r\n', 'GETINFO')
    self.assertEqual('hi right back!', self.controller.get_info('hello'))

  @patch('stem.control.Controller.msg')
  def test_get_info_address_caching(self, msg_mock):
    msg_mock.return_value = ControlMessage.from_str('551 Address unknown\r\n')

    self.assertEqual(None, self.controller._last_address_exc)
    self.assertRaisesWith(stem.OperationFailed, 'Address unknown', self.controller.get_info, 'address')
    self.assertEqual('Address unknown', str(self.controller._last_address_exc))
    self.assertEqual(1, msg_mock.call_count)

    # now that we have a cached failure we should provide that back

    self.assertRaisesWith(stem.OperationFailed, 'Address unknown', self.controller.get_info, 'address')
    self.assertEqual(1, msg_mock.call_count)

    # invalidates the cache, transitioning from no address to having one

    msg_mock.return_value = ControlMessage.from_str('250-address=17.2.89.80\r\n250 OK\r\n', 'GETINFO')
    self.assertRaisesWith(stem.OperationFailed, 'Address unknown', self.controller.get_info, 'address')
    self.controller._handle_event(ControlMessage.from_str('650 STATUS_SERVER NOTICE EXTERNAL_ADDRESS ADDRESS=17.2.89.80 METHOD=DIRSERV\r\n'))
    self.assertEqual('17.2.89.80', self.controller.get_info('address'))

    # invalidates the cache, transitioning from one address to another

    msg_mock.return_value = ControlMessage.from_str('250-address=80.89.2.17\r\n250 OK\r\n', 'GETINFO')
    self.assertEqual('17.2.89.80', self.controller.get_info('address'))
    self.controller._handle_event(ControlMessage.from_str('650 STATUS_SERVER NOTICE EXTERNAL_ADDRESS ADDRESS=80.89.2.17 METHOD=DIRSERV\r\n'))
    self.assertEqual('80.89.2.17', self.controller.get_info('address'))

  @patch('stem.control.Controller.msg')
  @patch('stem.control.Controller.get_conf')
  def test_get_info_without_fingerprint(self, get_conf_mock, msg_mock):
    msg_mock.return_value = ControlMessage.from_str('551 Not running in server mode\r\n')
    get_conf_mock.return_value = None

    self.assertEqual(None, self.controller._last_fingerprint_exc)
    self.assertRaisesWith(stem.OperationFailed, 'Not running in server mode', self.controller.get_info, 'fingerprint')
    self.assertEqual('Not running in server mode', str(self.controller._last_fingerprint_exc))
    self.assertEqual(1, msg_mock.call_count)

    # now that we have a cached failure we should provide that back

    self.assertRaisesWith(stem.OperationFailed, 'Not running in server mode', self.controller.get_info, 'fingerprint')
    self.assertEqual(1, msg_mock.call_count)

    # ... but if we become a relay we'll call it again

    get_conf_mock.return_value = '443'
    self.assertRaisesWith(stem.OperationFailed, 'Not running in server mode', self.controller.get_info, 'fingerprint')
    self.assertEqual(2, msg_mock.call_count)

  @patch('stem.control.Controller.get_info')
  def test_get_version(self, get_info_mock):
    """
    Exercises the get_version() method.
    """

    try:
      # Use one version for first check.
      version_2_1 = '0.2.1.32'
      version_2_1_object = stem.version.Version(version_2_1)
      get_info_mock.return_value = version_2_1

      # Return a version with a cold cache.
      self.assertEqual(version_2_1_object, self.controller.get_version())

      # Use a different version for second check.
      version_2_2 = '0.2.2.39'
      version_2_2_object = stem.version.Version(version_2_2)
      get_info_mock.return_value = version_2_2

      # Return a version with a hot cache, so it will be the old version.
      self.assertEqual(version_2_1_object, self.controller.get_version())

      # Turn off caching.
      self.controller._is_caching_enabled = False
      # Return a version without caching, so it will be the new version.
      self.assertEqual(version_2_2_object, self.controller.get_version())

      # Spec says the getinfo response may optionally be prefixed by 'Tor '. In
      # practice it doesn't but we should accept that.
      get_info_mock.return_value = 'Tor 0.2.1.32'
      self.assertEqual(version_2_1_object, self.controller.get_version())

      # Raise an exception in the get_info() call.
      get_info_mock.side_effect = InvalidArguments

      # Get a default value when the call fails.
      self.assertEqual(
        'default returned',
        self.controller.get_version(default = 'default returned')
      )

      # No default value, accept the error.
      self.assertRaises(InvalidArguments, self.controller.get_version)

      # Give a bad version.  The stem.version.Version ValueError should bubble up.
      version_A_42 = '0.A.42.spam'
      get_info_mock.return_value = version_A_42
      get_info_mock.side_effect = None
      self.assertRaises(ValueError, self.controller.get_version)
    finally:
      # Turn caching back on before we leave.
      self.controller._is_caching_enabled = True

  @patch('stem.control.Controller.get_info')
  def test_get_exit_policy(self, get_info_mock):
    """
    Exercises the get_exit_policy() method.
    """

    get_info_mock.side_effect = lambda param, default = None: {
      'exit-policy/full': 'reject *:25,reject *:119,reject *:135-139,reject *:445,reject *:563,reject *:1214,reject *:4661-4666,reject *:6346-6429,reject *:6699,reject *:6881-6999,accept *:*',
    }[param]

    expected = ExitPolicy(
      'reject *:25',
      'reject *:119',
      'reject *:135-139',
      'reject *:445',
      'reject *:563',
      'reject *:1214',
      'reject *:4661-4666',
      'reject *:6346-6429',
      'reject *:6699',
      'reject *:6881-6999',
      'accept *:*',
    )

    self.assertEqual(str(expected), str(self.controller.get_exit_policy()))

  @patch('stem.control.Controller.get_info')
  @patch('stem.control.Controller.get_conf')
  def test_get_exit_policy_if_not_relaying(self, get_conf_mock, get_info_mock):
    # If tor lacks an ORPort, resolved extrnal address, hasn't finished making
    # our server descriptor (ie. tor just started), etc 'GETINFO
    # exit-policy/full' will fail.

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'ExitRelay': '1',
      'ExitPolicyRejectPrivate': '1',
      'ExitPolicy': ['accept *:80,   accept *:443', 'accept 43.5.5.5,reject *:22'],
    }[param]

    expected = ExitPolicy(
      'reject 0.0.0.0/8:*',
      'reject 169.254.0.0/16:*',
      'reject 127.0.0.0/8:*',
      'reject 192.168.0.0/16:*',
      'reject 10.0.0.0/8:*',
      'reject 172.16.0.0/12:*',
      'reject 1.2.3.4:*',
      'accept *:80',
      'accept *:443',
      'accept 43.5.5.5:*',
      'reject *:22',
    )

    # Unfortunate it's a bit tricky to have a mock that raises exceptions in
    # response to some arguments, and returns a response for others. As such
    # mapping it to the following function.

    exit_policy_exception = None

    def getinfo_response(param, default = None):
      if param == 'address':
        return '1.2.3.4'
      elif param == 'exit-policy/default':
        return ''
      elif param == 'exit-policy/full' and exit_policy_exception:
        raise exit_policy_exception
      else:
        raise ValueError("Unmocked request for 'GETINFO %s'" % param)

    get_info_mock.side_effect = getinfo_response

    exit_policy_exception = stem.OperationFailed('552', 'Not running in server mode')
    self.assertEqual(str(expected), str(self.controller.get_exit_policy()))

    exit_policy_exception = stem.OperationFailed('551', 'Descriptor still rebuilding - not ready yet')
    self.assertEqual(str(expected), str(self.controller.get_exit_policy()))

  @patch('stem.control.Controller.get_info')
  @patch('stem.control.Controller.get_conf')
  def test_get_ports(self, get_conf_mock, get_info_mock):
    """
    Exercises the get_ports() and get_listeners() methods.
    """

    # Exercise as an old version of tor that doesn't support the 'GETINFO
    # net/listeners/*' options.

    get_info_mock.side_effect = InvalidArguments

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'ControlPort': '9050',
      'ControlListenAddress': ['127.0.0.1'],
    }[param]

    self.assertEqual([('127.0.0.1', 9050)], self.controller.get_listeners(Listener.CONTROL))
    self.assertEqual([9050], self.controller.get_ports(Listener.CONTROL))
    self.controller.clear_cache()

    # non-local addresss

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'ControlPort': '9050',
      'ControlListenAddress': ['27.4.4.1'],
    }[param]

    self.assertEqual([('27.4.4.1', 9050)], self.controller.get_listeners(Listener.CONTROL))
    self.assertEqual([], self.controller.get_ports(Listener.CONTROL))
    self.controller.clear_cache()

    # exercise via the GETINFO option

    get_info_mock.side_effect = None
    get_info_mock.return_value = '"127.0.0.1:1112" "127.0.0.1:1114"'

    self.assertEqual(
      [('127.0.0.1', 1112), ('127.0.0.1', 1114)],
      self.controller.get_listeners(Listener.CONTROL)
    )

    self.assertEqual([1112, 1114], self.controller.get_ports(Listener.CONTROL))
    self.controller.clear_cache()

    # with all localhost addresses, including a couple that aren't

    get_info_mock.side_effect = None
    get_info_mock.return_value = '"27.4.4.1:1113" "127.0.0.5:1114" "0.0.0.0:1115" "[::]:1116" "[::1]:1117" "[10::]:1118"'

    self.assertEqual([1114, 1115, 1116, 1117], self.controller.get_ports(Listener.OR))
    self.controller.clear_cache()

    # IPv6 address

    get_info_mock.return_value = '"0.0.0.0:9001" "[fe80:0000:0000:0000:0202:b3ff:fe1e:8329]:9001"'

    self.assertEqual(
      [('0.0.0.0', 9001), ('fe80:0000:0000:0000:0202:b3ff:fe1e:8329', 9001)],
      self.controller.get_listeners(Listener.CONTROL)
    )

    # unix socket file

    self.controller.clear_cache()
    get_info_mock.return_value = '"unix:/tmp/tor/socket"'

    self.assertEqual([], self.controller.get_listeners(Listener.CONTROL))
    self.assertEqual([], self.controller.get_ports(Listener.CONTROL))

  @patch('stem.control.Controller.get_info')
  @patch('stem.control.Controller.get_conf')
  def test_get_socks_listeners_old(self, get_conf_mock, get_info_mock):
    """
    Exercises the get_socks_listeners() method as though talking to an old tor
    instance.
    """

    # An old tor raises stem.InvalidArguments for get_info about socks, but
    # get_socks_listeners should work anyway.

    get_info_mock.side_effect = InvalidArguments

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': '9050',
      'SocksListenAddress': ['127.0.0.1'],
    }[param]

    self.assertEqual([('127.0.0.1', 9050)], self.controller.get_socks_listeners())
    self.controller.clear_cache()

    # Again, an old tor, but SocksListenAddress overrides the port number.

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': '9050',
      'SocksListenAddress': ['127.0.0.1:1112'],
    }[param]

    self.assertEqual([('127.0.0.1', 1112)], self.controller.get_socks_listeners())
    self.controller.clear_cache()

    # Again, an old tor, but multiple listeners

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': '9050',
      'SocksListenAddress': ['127.0.0.1:1112', '127.0.0.1:1114'],
    }[param]

    self.assertEqual([('127.0.0.1', 1112), ('127.0.0.1', 1114)], self.controller.get_socks_listeners())
    self.controller.clear_cache()

    # Again, an old tor, but no SOCKS listeners

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': '0',
      'SocksListenAddress': [],
    }[param]

    self.assertEqual([], self.controller.get_socks_listeners())
    self.controller.clear_cache()

    # Where tor provides invalid ports or addresses

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': 'blarg',
      'SocksListenAddress': ['127.0.0.1'],
    }[param]

    self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': '0',
      'SocksListenAddress': ['127.0.0.1:abc'],
    }[param]

    self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'SocksPort': '40',
      'SocksListenAddress': ['500.0.0.1'],
    }[param]

    self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)

  @patch('stem.control.Controller.get_info')
  def test_get_socks_listeners_new(self, get_info_mock):
    """
    Exercises the get_socks_listeners() method as if talking to a newer tor
    instance.
    """

    # multiple SOCKS listeners

    get_info_mock.return_value = '"127.0.0.1:1112" "127.0.0.1:1114"'

    self.assertEqual(
      [('127.0.0.1', 1112), ('127.0.0.1', 1114)],
      self.controller.get_socks_listeners()
    )

    # no SOCKS listeners

    self.controller.clear_cache()
    get_info_mock.return_value = ''
    self.assertEqual([], self.controller.get_socks_listeners())

    # check where GETINFO provides malformed content

    invalid_responses = (
      '"127.0.0.1"',         # address only
      '"1112"',              # port only
      '"5127.0.0.1:1112"',   # invlaid address
      '"127.0.0.1:991112"',  # invalid port
    )

    for response in invalid_responses:
      self.controller.clear_cache()
      get_info_mock.return_value = response
      self.assertRaises(stem.ProtocolError, self.controller.get_socks_listeners)

  @patch('stem.control.Controller.get_info')
  @patch('time.time', Mock(return_value = 1410723598.276578))
  def test_get_accounting_stats(self, get_info_mock):
    """
    Exercises the get_accounting_stats() method.
    """

    get_info_mock.side_effect = lambda param, **kwargs: {
      'accounting/enabled': '1',
      'accounting/hibernating': 'awake',
      'accounting/interval-end': '2014-09-14 19:41:00',
      'accounting/bytes': '4837 2050',
      'accounting/bytes-left': '102944 7440',
    }[param]

    expected = stem.control.AccountingStats(
      1410723598.276578,
      'awake',
      datetime.datetime(2014, 9, 14, 19, 41),
      62,
      4837, 102944, 107781,
      2050, 7440, 9490,
    )

    self.assertEqual(expected, self.controller.get_accounting_stats())

    get_info_mock.side_effect = ControllerError('nope, too bad')
    self.assertRaises(ControllerError, self.controller.get_accounting_stats)
    self.assertEqual('my default', self.controller.get_accounting_stats('my default'))

  @patch('stem.connection.get_protocolinfo')
  def test_get_protocolinfo(self, get_protocolinfo_mock):
    """
    Exercises the get_protocolinfo() method.
    """

    # use the handy mocked protocolinfo response

    protocolinfo_msg = ControlMessage.from_str('250-PROTOCOLINFO 1\r\n250 OK\r\n', 'PROTOCOLINFO')
    get_protocolinfo_mock.return_value = protocolinfo_msg

    # compare the str representation of these object, because the class
    # does not have, nor need, a direct comparison operator

    self.assertEqual(
      str(protocolinfo_msg),
      str(self.controller.get_protocolinfo())
    )

    # raise an exception in the stem.connection.get_protocolinfo() call

    get_protocolinfo_mock.side_effect = ProtocolError

    # get a default value when the call fails

    self.assertEqual(
      'default returned',
      self.controller.get_protocolinfo(default = 'default returned')
    )

    # no default value, accept the error

    self.assertRaises(ProtocolError, self.controller.get_protocolinfo)

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = False))
  def test_get_user_remote(self):
    """
    Exercise the get_user() method for a non-local socket.
    """

    self.assertRaises(ValueError, self.controller.get_user)
    self.assertEqual(123, self.controller.get_user(123))

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = True))
  @patch('stem.control.Controller.get_info', Mock(return_value = 'atagar'))
  def test_get_user_by_getinfo(self):
    """
    Exercise the get_user() resolution via its getinfo option.
    """

    self.assertEqual('atagar', self.controller.get_user())

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = True))
  @patch('stem.util.system.pid_by_name', Mock(return_value = 432))
  @patch('stem.util.system.user', Mock(return_value = 'atagar'))
  def test_get_user_by_system(self):
    """
    Exercise the get_user() resolution via the system module.
    """

    self.assertEqual('atagar', self.controller.get_user())

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = False))
  def test_get_pid_remote(self):
    """
    Exercise the get_pid() method for a non-local socket.
    """

    self.assertRaises(ValueError, self.controller.get_pid)
    self.assertEqual(123, self.controller.get_pid(123))

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = True))
  @patch('stem.control.Controller.get_info', Mock(return_value = '321'))
  def test_get_pid_by_getinfo(self):
    """
    Exercise the get_pid() resolution via its getinfo option.
    """

    self.assertEqual(321, self.controller.get_pid())

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = True))
  @patch('stem.control.Controller.get_conf')
  @patch('stem.control.open', create = True)
  def test_get_pid_by_pid_file(self, open_mock, get_conf_mock):
    """
    Exercise the get_pid() resolution via a PidFile.
    """

    get_conf_mock.return_value = '/tmp/pid_file'
    open_mock.return_value = io.BytesIO(b'432')

    self.assertEqual(432, self.controller.get_pid())
    open_mock.assert_called_once_with('/tmp/pid_file')

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = True))
  @patch('stem.util.system.pid_by_name', Mock(return_value = 432))
  def test_get_pid_by_name(self):
    """
    Exercise the get_pid() resolution via the process name.
    """

    self.assertEqual(432, self.controller.get_pid())

  @patch('stem.control.Controller.get_version', Mock(return_value = stem.version.Version('0.5.0.14')))
  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = False))
  @patch('stem.control.Controller.get_info')
  @patch('time.time', Mock(return_value = 1000.0))
  def test_get_uptime_by_getinfo(self, getinfo_mock):
    """
    Exercise the get_uptime() resolution via a GETINFO query.
    """

    getinfo_mock.return_value = '321'
    self.assertEqual(321.0, self.controller.get_uptime())
    self.controller.clear_cache()

    getinfo_mock.return_value = 'abc'
    self.assertRaisesWith(ValueError, "'GETINFO uptime' did not provide a valid numeric response: abc", self.controller.get_uptime)

  @patch('stem.socket.ControlSocket.is_localhost', Mock(return_value = True))
  @patch('stem.control.Controller.get_version', Mock(return_value = stem.version.Version('0.1.0.14')))
  @patch('stem.control.Controller.get_pid', Mock(return_value = '12'))
  @patch('stem.util.system.start_time', Mock(return_value = 5000.0))
  @patch('time.time', Mock(return_value = 5200.0))
  def test_get_uptime_by_process(self):
    """
    Exercise the get_uptime() resolution via process age.
    """

    self.assertEqual(200.0, self.controller.get_uptime())

  @patch('stem.control.Controller.get_info')
  def test_get_network_status_for_ourselves(self, get_info_mock):
    """
    Exercises the get_network_status() method for getting our own relay.
    """

    # when there's an issue getting our fingerprint

    get_info_mock.side_effect = ControllerError('nope, too bad')

    exc_msg = 'Unable to determine our own fingerprint: nope, too bad'
    self.assertRaisesWith(ControllerError, exc_msg, self.controller.get_network_status)
    self.assertEqual('boom', self.controller.get_network_status(default = 'boom'))

    # successful request

    desc = NS_DESC % ('moria1', '/96bKo4soysolMgKn5Hex2nyFSY')

    get_info_mock.side_effect = lambda param, **kwargs: {
      'fingerprint': '9695DFC35FFEB861329B9F1AB04C46397020CE31',
      'ns/id/9695DFC35FFEB861329B9F1AB04C46397020CE31': desc,
    }[param]

    self.assertEqual(stem.descriptor.router_status_entry.RouterStatusEntryV3(desc), self.controller.get_network_status())

  @patch('stem.control.Controller.get_info')
  def test_get_network_status_when_unavailable(self, get_info_mock):
    """
    Exercises the get_network_status() method.
    """

    get_info_mock.side_effect = InvalidArguments(None, 'GETINFO request contained unrecognized keywords: ns/id/5AC9C5AA75BA1F18D8459B326B4B8111A856D290')

    exc_msg = "Tor was unable to provide the descriptor for '5AC9C5AA75BA1F18D8459B326B4B8111A856D290'"
    self.assertRaisesWith(DescriptorUnavailable, exc_msg, self.controller.get_network_status, '5AC9C5AA75BA1F18D8459B326B4B8111A856D290')

  @patch('stem.control.Controller.get_info')
  def test_get_network_status(self, get_info_mock):
    """
    Exercises the get_network_status() method.
    """

    # build a single router status entry

    nickname = 'Beaver'
    fingerprint = '/96bKo4soysolMgKn5Hex2nyFSY'
    desc = NS_DESC % (nickname, fingerprint)
    router = stem.descriptor.router_status_entry.RouterStatusEntryV3(desc)

    # always return the same router status entry

    get_info_mock.return_value = desc

    # pretend to get the router status entry with its name

    self.assertEqual(router, self.controller.get_network_status(nickname))

    # pretend to get the router status entry with its fingerprint

    hex_fingerprint = stem.descriptor.router_status_entry._base64_to_hex(fingerprint, False)
    self.assertEqual(router, self.controller.get_network_status(hex_fingerprint))

    # mangle hex fingerprint and try again

    hex_fingerprint = hex_fingerprint[2:]
    self.assertRaises(ValueError, self.controller.get_network_status, hex_fingerprint)

    # raise an exception in the get_info() call

    get_info_mock.side_effect = InvalidArguments

    # get a default value when the call fails

    self.assertEqual(
      'default returned',
      self.controller.get_network_status(nickname, default = 'default returned')
    )

    # no default value, accept the error

    self.assertRaises(InvalidArguments, self.controller.get_network_status, nickname)

  @patch('stem.control.Controller.is_authenticated', Mock(return_value = True))
  @patch('stem.control.Controller._attach_listeners', Mock(return_value = ([], [])))
  @patch('stem.control.Controller.get_version')
  def test_add_event_listener(self, get_version_mock):
    """
    Exercises the add_event_listener and remove_event_listener methods.
    """

    # set up for failure to create any events

    get_version_mock.return_value = stem.version.Version('0.1.0.14')
    self.assertRaises(InvalidRequest, self.controller.add_event_listener, Mock(), EventType.BW)

    # set up to only fail newer events

    get_version_mock.return_value = stem.version.Version('0.2.0.35')

    # EventType.BW is one of the earliest events

    self.controller.add_event_listener(Mock(), EventType.BW)

    # EventType.SIGNAL was added in tor version 0.2.3.1-alpha

    self.assertRaises(InvalidRequest, self.controller.add_event_listener, Mock(), EventType.SIGNAL)

  def test_events_get_received(self):
    """
    Trigger an event, checking that our listeners get notified.
    """

    self._emit_event(CIRC_EVENT)
    self.circ_listener.assert_called_once_with(CIRC_EVENT)
    self.bw_listener.assert_not_called()
    self.malformed_listener.assert_not_called()

    self._emit_event(BW_EVENT)
    self.bw_listener.assert_called_once_with(BW_EVENT)

  def test_event_listing_with_error(self):
    """
    Raise an exception in an event listener to confirm it doesn't break our
    event thread.
    """

    self.circ_listener.side_effect = ValueError('boom')

    self._emit_event(CIRC_EVENT)
    self.circ_listener.assert_called_once_with(CIRC_EVENT)
    self.bw_listener.assert_not_called()
    self.malformed_listener.assert_not_called()

    self._emit_event(BW_EVENT)
    self.bw_listener.assert_called_once_with(BW_EVENT)

  def test_event_listing_with_malformed_event(self):
    """
    Attempt to parse a malformed event emitted from Tor. It's important this
    doesn't break our event thread.
    """

    # When stem.response.convert() encounters malformed content we still recast
    # the message.

    expected_bad_event = ControlMessage.from_str(BAD_EVENT.raw_content())
    setattr(expected_bad_event, 'arrived_at', TEST_TIMESTAMP)
    expected_bad_event.__class__ = stem.response.events.BandwidthEvent

    self._emit_event(BAD_EVENT)
    self.circ_listener.assert_not_called()
    self.bw_listener.assert_not_called()
    self.malformed_listener.assert_called_once_with(expected_bad_event)

    self._emit_event(BW_EVENT)
    self.bw_listener.assert_called_once_with(BW_EVENT)

  @patch('stem.control.Controller.get_version', Mock(return_value = stem.version.Version('0.5.0.14')))
  @patch('stem.control.Controller.msg', Mock(return_value = ControlMessage.from_str('250 OK\r\n')))
  @patch('stem.control.Controller.add_event_listener', Mock())
  @patch('stem.control.Controller.remove_event_listener', Mock())
  def test_timeout(self):
    """
    Methods that have an 'await' argument also have an optional timeout. Check
    that we raise a Timeout exception when it's elapsed.
    """

    self.assertRaisesWith(stem.Timeout, 'Reached our 0.1 second timeout', self.controller.get_hidden_service_descriptor, '5g2upl4pq6kufc4m', await_result = True, timeout = 0.1)

  def test_get_streams(self):
    """
    Exercises the get_streams() method.
    """

    # get a list of fake, but good looking, streams
    valid_streams = (
      ('1', 'NEW', '4', '10.10.10.1:80'),
      ('2', 'SUCCEEDED', '4', '10.10.10.1:80'),
      ('3', 'SUCCEEDED', '4', '10.10.10.1:80')
    )

    response = ''.join(['%s\r\n' % ' '.join(entry) for entry in valid_streams])

    with patch('stem.control.Controller.get_info', Mock(return_value = response)):
      streams = self.controller.get_streams()
      self.assertEqual(len(valid_streams), len(streams))

      for index, stream in enumerate(streams):
        self.assertEqual(valid_streams[index][0], stream.id)
        self.assertEqual(valid_streams[index][1], stream.status)
        self.assertEqual(valid_streams[index][2], stream.circ_id)
        self.assertEqual(valid_streams[index][3], stream.target)

  def test_attach_stream(self):
    """
    Exercises the attach_stream() method.
    """

    # Response when the stream is in a state where it can't be attached (for
    # instance, it's already open).

    response = stem.response.ControlMessage.from_str('555 Connection is not managed by controller.\r\n')

    with patch('stem.control.Controller.msg', Mock(return_value = response)):
      self.assertRaises(UnsatisfiableRequest, self.controller.attach_stream, 'stream_id', 'circ_id')

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
      '=piyaz',  # no fingerprint
      '999A226EBED397F331B612FE1E4CFAE5C1F201BA=piyaz',  # fingerprint missing prefix
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BAA=piyaz',  # fingerprint too long
      '$999A226EBED397F331B612FE1E4CFAE5C1F201B=piyaz',  # fingerprint too short
      '$999A226EBED397F331B612FE1E4CFAE5C1F201Bz=piyaz',  # invalid character in fingerprint
      '$999A226EBED397F331B612FE1E4CFAE5C1F201BA=',  # no nickname
    ]

    for test_input in malformed_inputs:
      self.assertRaises(ProtocolError, _parse_circ_path, test_input)

  @patch('stem.control.Controller.get_conf')
  def test_get_effective_rate(self, get_conf_mock):
    """
    Exercise the get_effective_rate() method.
    """

    # check default if nothing was set

    get_conf_mock.side_effect = lambda param, **kwargs: {
      'BandwidthRate': '1073741824',
      'BandwidthBurst': '1073741824',
      'RelayBandwidthRate': '0',
      'RelayBandwidthBurst': '0',
      'MaxAdvertisedBandwidth': '1073741824',
    }[param]

    self.assertEqual(1073741824, self.controller.get_effective_rate())
    self.assertEqual(1073741824, self.controller.get_effective_rate(burst = True))

    get_conf_mock.side_effect = ControllerError('nope, too bad')
    self.assertRaises(ControllerError, self.controller.get_effective_rate)
    self.assertEqual('my_default', self.controller.get_effective_rate('my_default'))

  @patch('stem.control.Controller.get_version')
  def test_drop_guards(self, get_version_mock):
    """
    Exercises the drop_guards() method.
    """

    get_version_mock.return_value = stem.version.Version('0.1.0.14')
    self.assertRaises(UnsatisfiableRequest, self.controller.drop_guards)

    with patch('stem.control.Controller.msg', Mock(return_value = None)):
      get_version_mock.return_value = stem.version.Version('0.2.5.2')
      self.controller.drop_guards()

  def _emit_event(self, event):
    # Spins up our Controller's thread pool, emits an event, then shuts it
    # down. This last part is important for a couple reasons...
    #
    #   1. So we don't leave any lingering threads.
    #
    #   2. To ensure our event handlers are done being executed. Events are
    #      processed asynchronously, so the only way to endsure it's done
    #      with its work is to join on the thread.

    with patch('time.time', Mock(return_value = TEST_TIMESTAMP)):
      with patch('stem.control.Controller.is_alive') as is_alive_mock:
        is_alive_mock.return_value = True
        self.controller._launch_threads()

        try:
          # Converting an event back into an uncast ControlMessage, then feeding it
          # into our controller's event queue.

          uncast_event = ControlMessage.from_str(event.raw_content())
          self.controller._event_queue.put(uncast_event)
          self.controller._event_notice.set()
          self.controller._event_queue.join()  # block until the event is consumed
        finally:
          is_alive_mock.return_value = False
          self.controller._close()
