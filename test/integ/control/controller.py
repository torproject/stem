"""
Integration tests for the stem.control.Controller class.
"""

import hashlib
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest

import stem.connection
import stem.control
import stem.descriptor.reader
import stem.descriptor.router_status_entry
import stem.response.protocolinfo
import stem.socket
import stem.util.str_tools
import stem.version
import test.network
import test.runner

from stem import Flag, Signal
from stem.control import EventType, Listener, State
from stem.exit_policy import ExitPolicy
from stem.version import Requirement

from test.util import register_new_capability

from test.runner import (
  require_controller,
  require_version,
  require_online,
  only_run_once,
)

# Router status entry for a relay with a nickname other than 'Unnamed'. This is
# used for a few tests that need to look up a relay.

TEST_ROUTER_STATUS_ENTRY = None


def random_fingerprint():
  """
  Provides a random 40 character hex string.
  """

  return hashlib.sha1(os.urandom(20)).hexdigest().upper()


class TestController(unittest.TestCase):
  @only_run_once
  @require_controller
  def test_missing_capabilities(self):
    """
    Check to see if tor supports any events, signals, or features that we
    don't.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      for event in controller.get_info('events/names').split():
        if event not in EventType:
          register_new_capability('Event', event)

      for signal in controller.get_info('signal/names').split():
        if signal not in Signal:
          register_new_capability('Signal', signal)

      # new features should simply be added to enable_feature()'s docs

      for feature in controller.get_info('features/names').split():
        if feature not in ('EXTENDED_EVENTS', 'VERBOSE_NAMES'):
          register_new_capability('Feature', feature)

  def test_from_port(self):
    """
    Basic sanity check for the from_port constructor.
    """

    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      with stem.control.Controller.from_port(port = test.runner.CONTROL_PORT) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      self.assertRaises(stem.SocketError, stem.control.Controller.from_port, '127.0.0.1', test.runner.CONTROL_PORT)

  def test_from_socket_file(self):
    """
    Basic sanity check for the from_socket_file constructor.
    """

    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      with stem.control.Controller.from_socket_file(path = test.runner.CONTROL_SOCKET_PATH) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      self.assertRaises(stem.SocketError, stem.control.Controller.from_socket_file, test.runner.CONTROL_SOCKET_PATH)

  @require_controller
  @require_version(Requirement.EVENT_SIGNAL)
  def test_reset_notification(self):
    """
    Checks that a notificiation listener is... well, notified of SIGHUPs.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      received_events = []

      def status_listener(my_controller, state, timestamp):
        received_events.append((my_controller, state, timestamp))

      controller.add_status_listener(status_listener)

      before = time.time()
      controller.signal(Signal.HUP)

      # I really hate adding a sleep here, but signal() is non-blocking.
      while len(received_events) == 0:
        if (time.time() - before) > 2:
          self.fail("We've waited a couple seconds for SIGHUP to generate an event, but it didn't come")

        time.sleep(0.1)

      after = time.time()

      self.assertEqual(1, len(received_events))

      state_controller, state_type, state_timestamp = received_events[0]

      self.assertEqual(controller, state_controller)
      self.assertEqual(State.RESET, state_type)
      self.assertTrue(state_timestamp > before and state_timestamp < after)

      controller.reset_conf('__OwningControllerProcess')

  @require_controller
  def test_event_handling(self):
    """
    Add a couple listeners for various events and make sure that they receive
    them. Then remove the listeners.
    """

    event_notice1, event_notice2 = threading.Event(), threading.Event()
    event_buffer1, event_buffer2 = [], []

    def listener1(event):
      event_buffer1.append(event)
      event_notice1.set()

    def listener2(event):
      event_buffer2.append(event)
      event_notice2.set()

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      controller.add_event_listener(listener1, EventType.CONF_CHANGED)
      controller.add_event_listener(listener2, EventType.CONF_CHANGED, EventType.DEBUG)

      # The NodeFamily is a harmless option we can toggle
      controller.set_conf('NodeFamily', random_fingerprint())

      # Wait for the event. Assert that we get it within 10 seconds
      event_notice1.wait(10)
      self.assertEqual(len(event_buffer1), 1)
      event_notice1.clear()

      event_notice2.wait(10)
      self.assertTrue(len(event_buffer2) >= 1)
      event_notice2.clear()

      # Checking that a listener's no longer called after being removed.

      controller.remove_event_listener(listener2)

      buffer2_size = len(event_buffer2)

      controller.set_conf('NodeFamily', random_fingerprint())
      event_notice1.wait(10)
      self.assertEqual(len(event_buffer1), 2)
      event_notice1.clear()

      self.assertEqual(buffer2_size, len(event_buffer2))

      for event in event_buffer1:
        self.assertTrue(isinstance(event, stem.response.events.Event))
        self.assertEqual(0, len(event.positional_args))
        self.assertEqual({}, event.keyword_args)

        self.assertTrue(isinstance(event, stem.response.events.ConfChangedEvent))

      controller.reset_conf('NodeFamily')

  @require_controller
  def test_reattaching_listeners(self):
    """
    Checks that event listeners are re-attached when a controller disconnects
    then reconnects to tor.
    """

    event_notice = threading.Event()
    event_buffer = []

    def listener(event):
      event_buffer.append(event)
      event_notice.set()

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      controller.add_event_listener(listener, EventType.BW)

      # Get a BW event or two. These should be emitted each second but under
      # heavy system load that's not always the case.

      event_notice.wait(4)
      self.assertTrue(len(event_buffer) >= 1)

      # disconnect and check that we stop getting events

      controller.close()
      event_notice.clear()
      event_buffer = []

      event_notice.wait(2)
      self.assertTrue(len(event_buffer) == 0)

      # reconnect and check that we get events again

      controller.connect()
      controller.authenticate(password = test.runner.CONTROL_PASSWORD)

      event_notice.wait(4)
      self.assertTrue(len(event_buffer) >= 1)

      # disconnect

      controller.close()
      event_notice.clear()
      event_buffer = []

      # reconnect and check that we get events again

      controller.connect()
      stem.connection.authenticate(controller, password = test.runner.CONTROL_PASSWORD)

      event_notice.wait(4)
      self.assertTrue(len(event_buffer) >= 1)

      # disconnect

      controller.close()
      event_notice.clear()
      event_buffer = []

      # Reconnect and check that we get events again. This is being done by
      # calling AUTHENTICATE manually so skipping cookie auth.

      tor_options = test.runner.get_runner().get_options()

      if test.runner.Torrc.COOKIE not in tor_options:
        controller.connect()

        if test.runner.Torrc.PASSWORD in tor_options:
          controller.msg('AUTHENTICATE "%s"' % test.runner.CONTROL_PASSWORD)
        else:
          controller.msg('AUTHENTICATE')

        event_notice.wait(4)
        self.assertTrue(len(event_buffer) >= 1)

  @require_controller
  def test_getinfo(self):
    """
    Exercises GETINFO with valid and invalid queries.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      # successful single query

      torrc_path = runner.get_torrc_path()
      self.assertEqual(torrc_path, controller.get_info('config-file'))
      self.assertEqual(torrc_path, controller.get_info('config-file', 'ho hum'))

      expected = {'config-file': torrc_path}
      self.assertEqual(expected, controller.get_info(['config-file']))
      self.assertEqual(expected, controller.get_info(['config-file'], 'ho hum'))

      # successful batch query, we don't know the values so just checking for
      # the keys

      getinfo_params = set(['version', 'config-file', 'config/names'])
      self.assertEqual(getinfo_params, set(controller.get_info(['version', 'config-file', 'config/names']).keys()))

      # non-existant option

      self.assertRaises(stem.ControllerError, controller.get_info, 'blarg')
      self.assertEqual('ho hum', controller.get_info('blarg', 'ho hum'))

      # empty input

      self.assertRaises(stem.ControllerError, controller.get_info, '')
      self.assertEqual('ho hum', controller.get_info('', 'ho hum'))

      self.assertEqual({}, controller.get_info([]))
      self.assertEqual({}, controller.get_info([], {}))

  @require_controller
  def test_get_version(self):
    """
    Test that the convenient method get_version() works.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      version = controller.get_version()
      self.assertTrue(isinstance(version, stem.version.Version))
      self.assertEqual(version, runner.get_tor_version())

  @require_controller
  def test_get_exit_policy(self):
    """
    Sanity test for get_exit_policy(). We have the default policy (no
    ExitPolicy set) which is a little... long due to the boilerplate.
    """

    expected = ExitPolicy(
      'reject 0.0.0.0/8:*',
      'reject 169.254.0.0/16:*',
      'reject 127.0.0.0/8:*',
      'reject 192.168.0.0/16:*',
      'reject 10.0.0.0/8:*',
      'reject 172.16.0.0/12:*',
      # this is where 'reject [public_addr]:*' may or may not be
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

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      # We can't simply compare the policies because the tor policy may or may
      # not have a reject entry for our public address. Hence, stripping it
      # from the policy's string, then comparing those.

      policy_str = str(controller.get_exit_policy())

      public_addr_start = policy_str.find('reject 172.16.0.0/12:*') + 22
      public_addr_end = policy_str.find(', reject *:25')

      policy_str = policy_str[:public_addr_start] + policy_str[public_addr_end:]
      self.assertEqual(str(expected), policy_str)

  @require_controller
  def test_authenticate(self):
    """
    Test that the convenient method authenticate() works.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller(False) as controller:
      controller.authenticate(test.runner.CONTROL_PASSWORD)
      test.runner.exercise_controller(self, controller)

  @require_controller
  def test_protocolinfo(self):
    """
    Test that the convenient method protocolinfo() works.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller(False) as controller:
      protocolinfo = controller.get_protocolinfo()
      self.assertTrue(isinstance(protocolinfo, stem.response.protocolinfo.ProtocolInfoResponse))

      # Doing a sanity test on the ProtocolInfoResponse instance returned.
      tor_options = runner.get_options()
      tor_version = runner.get_tor_version()
      auth_methods = []

      if test.runner.Torrc.COOKIE in tor_options:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.COOKIE)

        if tor_version >= stem.version.Requirement.AUTH_SAFECOOKIE:
          auth_methods.append(stem.response.protocolinfo.AuthMethod.SAFECOOKIE)

      if test.runner.Torrc.PASSWORD in tor_options:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.PASSWORD)

      if not auth_methods:
        auth_methods.append(stem.response.protocolinfo.AuthMethod.NONE)

      self.assertEqual(tuple(auth_methods), protocolinfo.auth_methods)

  @require_controller
  def test_getconf(self):
    """
    Exercises GETCONF with valid and invalid queries.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      control_socket = controller.get_socket()

      if isinstance(control_socket, stem.socket.ControlPort):
        connection_value = str(control_socket.get_port())
        config_key = 'ControlPort'
      elif isinstance(control_socket, stem.socket.ControlSocketFile):
        connection_value = str(control_socket.get_socket_path())
        config_key = 'ControlSocket'

      # successful single query
      self.assertEqual(connection_value, controller.get_conf(config_key))
      self.assertEqual(connection_value, controller.get_conf(config_key, 'la-di-dah'))

      # succeessful batch query
      expected = {config_key: [connection_value]}
      self.assertEqual(expected, controller.get_conf_map([config_key]))
      self.assertEqual(expected, controller.get_conf_map([config_key], 'la-di-dah'))

      request_params = ['ControlPORT', 'dirport', 'datadirectory']
      reply_params = controller.get_conf_map(request_params, multiple=False).keys()
      self.assertEqual(set(request_params), set(reply_params))

      # queries an option that is unset

      self.assertEqual(None, controller.get_conf('HTTPSProxy'))
      self.assertEqual('la-di-dah', controller.get_conf('HTTPSProxy', 'la-di-dah'))
      self.assertEqual([], controller.get_conf('HTTPSProxy', [], multiple = True))

      # non-existant option(s)
      self.assertRaises(stem.InvalidArguments, controller.get_conf, 'blarg')
      self.assertEqual('la-di-dah', controller.get_conf('blarg', 'la-di-dah'))
      self.assertRaises(stem.InvalidArguments, controller.get_conf_map, 'blarg')
      self.assertEqual({'blarg': 'la-di-dah'}, controller.get_conf_map('blarg', 'la-di-dah'))

      self.assertRaises(stem.InvalidRequest, controller.get_conf_map, ['blarg', 'huadf'], multiple = True)
      self.assertEqual({'erfusdj': 'la-di-dah', 'afiafj': 'la-di-dah'}, controller.get_conf_map(['erfusdj', 'afiafj'], 'la-di-dah', multiple = True))

      # multivalue configuration keys
      nodefamilies = [('abc', 'xyz', 'pqrs'), ('mno', 'tuv', 'wxyz')]
      controller.msg('SETCONF %s' % ' '.join(['nodefamily="' + ','.join(x) + '"' for x in nodefamilies]))
      self.assertEqual([','.join(n) for n in nodefamilies], controller.get_conf('nodefamily', multiple = True))
      controller.msg('RESETCONF NodeFamily')

      # empty input
      self.assertEqual(None, controller.get_conf(''))
      self.assertEqual({}, controller.get_conf_map([]))
      self.assertEqual({}, controller.get_conf_map(['']))
      self.assertEqual(None, controller.get_conf('          '))
      self.assertEqual({}, controller.get_conf_map(['    ', '        ']))

      self.assertEqual('la-di-dah', controller.get_conf('', 'la-di-dah'))
      self.assertEqual({}, controller.get_conf_map('', 'la-di-dah'))
      self.assertEqual({}, controller.get_conf_map([], 'la-di-dah'))

  @require_controller
  def test_is_set(self):
    """
    Exercises our is_set() method.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      custom_options = controller._get_custom_options()
      self.assertTrue('ControlPort' in custom_options or 'ControlSocket' in custom_options)
      self.assertEqual('1', custom_options['DownloadExtraInfo'])
      self.assertEqual('127.0.0.1:1112', custom_options['SocksListenAddress'])

      self.assertTrue(controller.is_set('DownloadExtraInfo'))
      self.assertTrue(controller.is_set('SocksListenAddress'))
      self.assertFalse(controller.is_set('CellStatistics'))
      self.assertFalse(controller.is_set('ConnLimit'))

      # check we update when setting and resetting values

      controller.set_conf('ConnLimit', '1005')
      self.assertTrue(controller.is_set('ConnLimit'))

      controller.reset_conf('ConnLimit')
      self.assertFalse(controller.is_set('ConnLimit'))

  @require_controller
  def test_hidden_services_conf(self):
    """
    Exercises the hidden service family of methods (get_hidden_service_conf,
    set_hidden_service_conf, create_hidden_service, and remove_hidden_service).
    """

    runner = test.runner.get_runner()

    test_dir = runner.get_test_dir()
    service1_path = os.path.join(test_dir, 'test_hidden_service1')
    service2_path = os.path.join(test_dir, 'test_hidden_service2')
    service3_path = os.path.join(test_dir, 'test_hidden_service3')
    service4_path = os.path.join(test_dir, 'test_hidden_service4')
    empty_service_path = os.path.join(test_dir, 'test_hidden_service_empty')

    with runner.get_tor_controller() as controller:
      try:
        # initially we shouldn't be running any hidden services

        self.assertEqual({}, controller.get_hidden_service_conf())

        # try setting a blank config, shouldn't have any impact

        controller.set_hidden_service_conf({})
        self.assertEqual({}, controller.get_hidden_service_conf())

        # create a hidden service

        initialconf = {
          service1_path: {
            'HiddenServicePort': [
              (8020, '127.0.0.1', 8020),
              (8021, '127.0.0.1', 8021),
            ],
            'HiddenServiceVersion': '2',
          },
          service2_path: {
            'HiddenServiceAuthorizeClient': 'stealth a, b',
            'HiddenServicePort': [
              (8030, '127.0.0.1', 8030),
              (8031, '127.0.0.1', 8031),
              (8032, '127.0.0.1', 8032),
            ]
          },
          empty_service_path: {
            'HiddenServicePort': []
          }
        }

        controller.set_hidden_service_conf(initialconf)
        self.assertEqual(initialconf, controller.get_hidden_service_conf())

        # add already existing services, with/without explicit target

        self.assertEqual(None, controller.create_hidden_service(service1_path, 8020))
        self.assertEqual(None, controller.create_hidden_service(service1_path, 8021, target_port = 8021))
        self.assertEqual(initialconf, controller.get_hidden_service_conf())

        # add a new service, with/without explicit target

        hs_path = os.path.join(os.getcwd(), service3_path)
        hs_address1 = controller.create_hidden_service(hs_path, 8888).hostname
        hs_address2 = controller.create_hidden_service(hs_path, 8989, target_port = 8021).hostname

        self.assertEqual(hs_address1, hs_address2)
        self.assertTrue(hs_address1.endswith('.onion'))

        conf = controller.get_hidden_service_conf()
        self.assertEqual(4, len(conf))
        self.assertEqual(2, len(conf[hs_path]['HiddenServicePort']))

        # remove a hidden service, the service dir should still be there

        controller.remove_hidden_service(hs_path, 8888)
        self.assertEqual(4, len(controller.get_hidden_service_conf()))

        # remove a service completely, it should now be gone

        controller.remove_hidden_service(hs_path, 8989)
        self.assertEqual(3, len(controller.get_hidden_service_conf()))

        # add a new service, this time with client authentication

        hs_path = os.path.join(os.getcwd(), service4_path)
        hs_attributes = controller.create_hidden_service(hs_path, 8888, auth_type = 'basic', client_names = ['c1', 'c2'])

        self.assertEqual(2, len(hs_attributes.hostname.splitlines()))
        self.assertEqual(2, len(hs_attributes.hostname_for_client))
        self.assertTrue(hs_attributes.hostname_for_client['c1'].endswith('.onion'))
        self.assertTrue(hs_attributes.hostname_for_client['c2'].endswith('.onion'))

        conf = controller.get_hidden_service_conf()
        self.assertEqual(4, len(conf))
        self.assertEqual(1, len(conf[hs_path]['HiddenServicePort']))

        # remove a hidden service

        controller.remove_hidden_service(hs_path, 8888)
        self.assertEqual(3, len(controller.get_hidden_service_conf()))
      finally:
        controller.set_hidden_service_conf({})  # drop hidden services created during the test

        # clean up the hidden service directories created as part of this test

        for path in (service1_path, service2_path, service3_path, service4_path):
          try:
            shutil.rmtree(path)
          except:
            pass

  @require_controller
  @require_version(Requirement.ADD_ONION)
  def test_without_ephemeral_hidden_services(self):
    """
    Exercises ephemeral hidden service methods when none are present.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual([], controller.list_ephemeral_hidden_services())
      self.assertEqual([], controller.list_ephemeral_hidden_services(detached = True))
      self.assertEqual(False, controller.remove_ephemeral_hidden_service('gfzprpioee3hoppz'))

  @require_controller
  @require_version(Requirement.ADD_ONION)
  def test_with_ephemeral_hidden_services(self):
    """
    Exercises creating ephemeral hidden services and methods when they're
    present.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      for ports in (4567890, [4567, 4567890], {4567: '-:4567'}):
        try:
          # try creating a service with an invalid port
          response = controller.create_ephemeral_hidden_service(ports)
          self.fail("we should've raised a stem.ProtocolError")
        except stem.ProtocolError as exc:
          self.assertEqual("ADD_ONION response didn't have an OK status: Invalid VIRTPORT/TARGET", str(exc))

      response = controller.create_ephemeral_hidden_service(4567)
      self.assertEqual([response.service_id], controller.list_ephemeral_hidden_services())
      self.assertTrue(response.private_key is not None)
      self.assertEqual({}, response.client_auth)

      # drop the service

      self.assertEqual(True, controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], controller.list_ephemeral_hidden_services())

      # recreate the service with the same private key

      recreate_response = controller.create_ephemeral_hidden_service(4567, key_type = response.private_key_type, key_content = response.private_key)
      self.assertEqual([response.service_id], controller.list_ephemeral_hidden_services())
      self.assertEqual(response.service_id, recreate_response.service_id)

      # the response only includes the private key when making a new one

      self.assertEqual(None, recreate_response.private_key)
      self.assertEqual(None, recreate_response.private_key_type)

      # create a service where we never see the private key

      response = controller.create_ephemeral_hidden_service(4568, discard_key = True)
      self.assertTrue(response.service_id in controller.list_ephemeral_hidden_services())
      self.assertEqual(None, response.private_key)
      self.assertEqual(None, response.private_key_type)

      # other controllers shouldn't be able to see these hidden services

      with runner.get_tor_controller() as second_controller:
        self.assertEqual(2, len(controller.list_ephemeral_hidden_services()))
        self.assertEqual(0, len(second_controller.list_ephemeral_hidden_services()))

  @require_controller
  @require_version(Requirement.ADD_ONION_BASIC_AUTH)
  def test_with_ephemeral_hidden_services_basic_auth(self):
    """
    Exercises creating ephemeral hidden services that uses basic authentication.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      response = controller.create_ephemeral_hidden_service(4567, basic_auth = {'alice': 'nKwfvVPmTNr2k2pG0pzV4g', 'bob': None})
      self.assertEqual([response.service_id], controller.list_ephemeral_hidden_services())
      self.assertTrue(response.private_key is not None)
      self.assertEqual(['bob'], list(response.client_auth.keys()))  # newly created credentials were only created for bob

      # drop the service

      self.assertEqual(True, controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], controller.list_ephemeral_hidden_services())

  @require_controller
  @require_version(Requirement.ADD_ONION_BASIC_AUTH)
  def test_with_ephemeral_hidden_services_basic_auth_without_credentials(self):
    """
    Exercises creating ephemeral hidden services when attempting to use basic
    auth but not including any credentials.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      try:
        controller.create_ephemeral_hidden_service(4567, basic_auth = {})
        self.fail('ADD_ONION should fail when using basic auth without any clients')
      except stem.ProtocolError as exc:
        self.assertEqual("ADD_ONION response didn't have an OK status: No auth clients specified", str(exc))

  @require_controller
  @require_version(Requirement.ADD_ONION)
  def test_with_detached_ephemeral_hidden_services(self):
    """
    Exercises creating detached ephemeral hidden services and methods when
    they're present.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      response = controller.create_ephemeral_hidden_service(4567, detached = True)
      self.assertEqual([], controller.list_ephemeral_hidden_services())
      self.assertEqual([response.service_id], controller.list_ephemeral_hidden_services(detached = True))

      # drop and recreate the service

      self.assertEqual(True, controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], controller.list_ephemeral_hidden_services(detached = True))
      controller.create_ephemeral_hidden_service(4567, key_type = response.private_key_type, key_content = response.private_key, detached = True)
      self.assertEqual([response.service_id], controller.list_ephemeral_hidden_services(detached = True))

      # other controllers should be able to see this service, and drop it

      with runner.get_tor_controller() as second_controller:
        self.assertEqual([response.service_id], second_controller.list_ephemeral_hidden_services(detached = True))
        self.assertEqual(True, second_controller.remove_ephemeral_hidden_service(response.service_id))
        self.assertEqual([], controller.list_ephemeral_hidden_services(detached = True))

        # recreate the service and confirms that it outlives this controller

        response = second_controller.create_ephemeral_hidden_service(4567, detached = True)

      self.assertEqual([response.service_id], controller.list_ephemeral_hidden_services(detached = True))
      controller.remove_ephemeral_hidden_service(response.service_id)

  @require_controller
  def test_set_conf(self):
    """
    Exercises set_conf(), reset_conf(), and set_options() methods with valid
    and invalid requests.
    """

    runner = test.runner.get_runner()
    tmpdir = tempfile.mkdtemp()

    with runner.get_tor_controller() as controller:
      try:
        # successfully set a single option
        connlimit = int(controller.get_conf('ConnLimit'))
        controller.set_conf('connlimit', str(connlimit - 1))
        self.assertEqual(connlimit - 1, int(controller.get_conf('ConnLimit')))

        # successfully set a single list option
        exit_policy = ['accept *:7777', 'reject *:*']
        controller.set_conf('ExitPolicy', exit_policy)
        self.assertEqual(exit_policy, controller.get_conf('ExitPolicy', multiple = True))

        # fail to set a single option
        try:
          controller.set_conf('invalidkeyboo', 'abcde')
          self.fail()
        except stem.InvalidArguments as exc:
          self.assertEqual(['invalidkeyboo'], exc.arguments)

        # resets configuration parameters
        controller.reset_conf('ConnLimit', 'ExitPolicy')
        self.assertEqual(connlimit, int(controller.get_conf('ConnLimit')))
        self.assertEqual(None, controller.get_conf('ExitPolicy'))

        # successfully sets multiple config options
        controller.set_options({
          'connlimit': str(connlimit - 2),
          'contactinfo': 'stem@testing',
        })

        self.assertEqual(connlimit - 2, int(controller.get_conf('ConnLimit')))
        self.assertEqual('stem@testing', controller.get_conf('contactinfo'))

        # fail to set multiple config options
        try:
          controller.set_options({
            'contactinfo': 'stem@testing',
            'bombay': 'vadapav',
          })
          self.fail()
        except stem.InvalidArguments as exc:
          self.assertEqual(['bombay'], exc.arguments)

        # context-sensitive keys (the only retched things for which order matters)
        controller.set_options((
          ('HiddenServiceDir', tmpdir),
          ('HiddenServicePort', '17234 127.0.0.1:17235'),
        ))

        self.assertEqual(tmpdir, controller.get_conf('HiddenServiceDir'))
        self.assertEqual('17234 127.0.0.1:17235', controller.get_conf('HiddenServicePort'))
      finally:
        # reverts configuration changes
        controller.set_options((
          ('ExitPolicy', 'reject *:*'),
          ('ConnLimit', None),
          ('ContactInfo', None),
          ('HiddenServiceDir', None),
          ('HiddenServicePort', None),
        ), reset = True)

        shutil.rmtree(tmpdir)

  @require_controller
  @require_version(Requirement.LOADCONF)
  def test_loadconf(self):
    """
    Exercises Controller.load_conf with valid and invalid requests.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      oldconf = runner.get_torrc_contents()

      try:
        # Check a request that changes our DataDir. Tor should rightfully balk
        # at this...
        #
        #   InvalidRequest: Transition not allowed: Failed to parse/validate
        #   config: While Tor is running, changing DataDirectory
        #   ("/home/atagar/Desktop/stem/test/data"->"/home/atagar/.tor") is not
        #   allowed.

        self.assertRaises(stem.InvalidRequest, controller.load_conf, 'ContactInfo confloaded')

        try:
          controller.load_conf('Blahblah blah')
          self.fail()
        except stem.InvalidArguments as exc:
          self.assertEqual(['Blahblah'], exc.arguments)

        # valid config

        controller.load_conf(runner.get_torrc_contents() + '\nContactInfo confloaded\n')
        self.assertEqual('confloaded', controller.get_conf('ContactInfo'))
      finally:
        # reload original valid config
        controller.load_conf(oldconf)
        controller.reset_conf('__OwningControllerProcess')

  @require_controller
  def test_saveconf(self):
    runner = test.runner.get_runner()

    # only testing for success, since we need to run out of disk space to test
    # for failure
    with runner.get_tor_controller() as controller:
      oldconf = runner.get_torrc_contents()

      try:
        controller.set_conf('ContactInfo', 'confsaved')
        controller.save_conf()

        with open(runner.get_torrc_path()) as torrcfile:
          self.assertTrue('\nContactInfo confsaved\n' in torrcfile.read())
      finally:
        controller.load_conf(oldconf)
        controller.save_conf()
        controller.reset_conf('__OwningControllerProcess')

  @require_controller
  def test_get_ports(self):
    """
    Test Controller.get_ports against a running tor instance.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      self.assertEqual([], controller.get_ports(Listener.OR))
      self.assertEqual([], controller.get_ports(Listener.DIR))
      self.assertEqual([test.runner.SOCKS_PORT], controller.get_ports(Listener.SOCKS))
      self.assertEqual([], controller.get_ports(Listener.TRANS))
      self.assertEqual([], controller.get_ports(Listener.NATD))
      self.assertEqual([], controller.get_ports(Listener.DNS))

      if test.runner.Torrc.PORT in runner.get_options():
        self.assertEqual([test.runner.CONTROL_PORT], controller.get_ports(Listener.CONTROL))
      else:
        self.assertEqual([], controller.get_ports(Listener.CONTROL))

  @require_controller
  def test_get_listeners(self):
    """
    Test Controller.get_listeners against a running tor instance.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      self.assertEqual([], controller.get_listeners(Listener.OR))
      self.assertEqual([], controller.get_listeners(Listener.DIR))
      self.assertEqual([('127.0.0.1', test.runner.SOCKS_PORT)], controller.get_listeners(Listener.SOCKS))
      self.assertEqual([], controller.get_listeners(Listener.TRANS))
      self.assertEqual([], controller.get_listeners(Listener.NATD))
      self.assertEqual([], controller.get_listeners(Listener.DNS))

      if test.runner.Torrc.PORT in runner.get_options():
        self.assertEqual([('127.0.0.1', test.runner.CONTROL_PORT)], controller.get_listeners(Listener.CONTROL))
      else:
        self.assertEqual([], controller.get_listeners(Listener.CONTROL))

  @require_controller
  def test_get_socks_listeners(self):
    """
    Test Controller.get_socks_listeners against a running tor instance.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual([('127.0.0.1', 1112)], controller.get_socks_listeners())

  @require_controller
  @require_online
  @require_version(stem.version.Version('0.1.2.2-alpha'))
  def test_enable_feature(self):
    """
    Test Controller.enable_feature with valid and invalid inputs.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      self.assertTrue(controller.is_feature_enabled('VERBOSE_NAMES'))

      self.assertTrue('VERBOSE_NAMES' in controller._enabled_features)
      self.assertRaises(stem.InvalidArguments, controller.enable_feature, ['NOT', 'A', 'FEATURE'])

      try:
        controller.enable_feature(['NOT', 'A', 'FEATURE'])
      except stem.InvalidArguments as exc:
        self.assertEqual(['NOT'], exc.arguments)
      else:
        self.fail()

  @require_controller
  def test_signal(self):
    """
    Test controller.signal with valid and invalid signals.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      # valid signal
      controller.signal('CLEARDNSCACHE')

      # invalid signals
      self.assertRaises(stem.InvalidArguments, controller.signal, 'FOOBAR')

  @require_controller
  def test_newnym_availability(self):
    """
    Test the is_newnym_available and get_newnym_wait methods.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual(True, controller.is_newnym_available())
      self.assertEqual(0.0, controller.get_newnym_wait())

      controller.signal(stem.Signal.NEWNYM)

      self.assertEqual(False, controller.is_newnym_available())
      self.assertTrue(controller.get_newnym_wait() > 9.0)

  @require_controller
  @require_online
  @require_version(Requirement.EXTENDCIRCUIT_PATH_OPTIONAL)
  def test_extendcircuit(self):
    with test.runner.get_runner().get_tor_controller() as controller:
      circuit_id = controller.extend_circuit('0')

      # check if our circuit was created
      self.assertNotEqual(None, controller.get_circuit(circuit_id, None))
      circuit_id = controller.new_circuit()
      self.assertNotEqual(None, controller.get_circuit(circuit_id, None))

      self.assertRaises(stem.InvalidRequest, controller.extend_circuit, 'foo')
      self.assertRaises(stem.InvalidRequest, controller.extend_circuit, '0', 'thisroutershouldntexistbecausestemexists!@##$%#')
      self.assertRaises(stem.InvalidRequest, controller.extend_circuit, '0', 'thisroutershouldntexistbecausestemexists!@##$%#', 'foo')

  @require_controller
  @require_online
  @require_version(Requirement.EXTENDCIRCUIT_PATH_OPTIONAL)
  def test_repurpose_circuit(self):
    """
    Tests Controller.repurpose_circuit with valid and invalid input.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      circ_id = controller.new_circuit()
      controller.repurpose_circuit(circ_id, 'CONTROLLER')
      circuit = controller.get_circuit(circ_id)
      self.assertTrue(circuit.purpose == 'CONTROLLER')

      controller.repurpose_circuit(circ_id, 'GENERAL')
      circuit = controller.get_circuit(circ_id)
      self.assertTrue(circuit.purpose == 'GENERAL')

      self.assertRaises(stem.InvalidRequest, controller.repurpose_circuit, 'f934h9f3h4', 'fooo')
      self.assertRaises(stem.InvalidRequest, controller.repurpose_circuit, '4', 'fooo')

  @require_controller
  @require_online
  @require_version(Requirement.EXTENDCIRCUIT_PATH_OPTIONAL)
  def test_close_circuit(self):
    """
    Tests Controller.close_circuit with valid and invalid input.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      circuit_id = controller.new_circuit()
      controller.close_circuit(circuit_id)
      circuit_output = controller.get_info('circuit-status')
      circ = [x.split()[0] for x in circuit_output.splitlines()]
      self.assertFalse(circuit_id in circ)

      circuit_id = controller.new_circuit()
      controller.close_circuit(circuit_id, 'IfUnused')
      circuit_output = controller.get_info('circuit-status')
      circ = [x.split()[0] for x in circuit_output.splitlines()]
      self.assertFalse(circuit_id in circ)

      circuit_id = controller.new_circuit()
      self.assertRaises(stem.InvalidArguments, controller.close_circuit, circuit_id + '1024')
      self.assertRaises(stem.InvalidRequest, controller.close_circuit, '')

  @require_controller
  @require_online
  def test_get_streams(self):
    """
    Tests Controller.get_streams().
    """

    host = socket.gethostbyname('www.torproject.org')
    port = 443

    runner = test.runner.get_runner()
    with runner.get_tor_controller() as controller:
      # we only need one proxy port, so take the first
      socks_listener = controller.get_socks_listeners()[0]

      with test.network.Socks(socks_listener) as s:
        s.settimeout(30)
        s.connect((host, port))
        streams = controller.get_streams()

    # Because we do not get a stream id when opening a stream,
    #  try to match the target for which we asked a stream.

    self.assertTrue('%s:%s' % (host, port) in [stream.target for stream in streams])

  @require_controller
  @require_online
  def test_close_stream(self):
    """
    Tests Controller.close_stream with valid and invalid input.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      # use the first socks listener

      socks_listener = controller.get_socks_listeners()[0]

      with test.network.Socks(socks_listener) as s:
        s.settimeout(30)
        s.connect(('www.torproject.org', 443))

        # There's only one stream right now.  Right?

        built_stream = controller.get_streams()[0]

        # Make sure we have the stream for which we asked, otherwise
        # the next assertion would be a false positive.

        self.assertEqual([built_stream.id], [stream.id for stream in controller.get_streams()])

        # Try to close our stream...

        controller.close_stream(built_stream.id)

        # ...which means there are zero streams.

        self.assertEqual([], controller.get_streams())

      # unknown stream

      self.assertRaises(stem.InvalidArguments, controller.close_stream, 'blarg')

  @require_controller
  @require_online
  def test_mapaddress(self):
    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      controller.map_address({'1.2.1.2': 'ifconfig.me'})

      s = None
      response = None

      # try up to 10 times to rule out transient network failures

      for _ in range(10):
        try:
          s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          s.settimeout(30)
          s.connect(('127.0.0.1', int(controller.get_conf('SocksListenAddress').rsplit(':', 1)[1])))
          test.network.negotiate_socks(s, '1.2.1.2', 80)
          s.sendall(stem.util.str_tools._to_bytes(test.network.ip_request))  # make the http request for the ip address
          response = s.recv(1000)

          if response:
            break
        except (stem.ProtocolError, socket.timeout):
          continue
        finally:
          if s:
            s.close()

      self.assertTrue(response)

      # everything after the blank line is the 'data' in a HTTP response.
      # The response data for our request for request should be an IP address + '\n'

      ip_addr = response[response.find(b'\r\n\r\n'):].strip()
      self.assertTrue(stem.util.connection.is_valid_ipv4_address(stem.util.str_tools._to_unicode(ip_addr)), "'%s' isn't an address" % ip_addr)

  @require_controller
  @require_online
  @require_version(Requirement.MICRODESCRIPTOR_IS_DEFAULT)
  def test_get_microdescriptor(self):
    """
    Basic checks for get_microdescriptor().
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      # we should balk at invalid content
      self.assertRaises(ValueError, controller.get_microdescriptor, '')
      self.assertRaises(ValueError, controller.get_microdescriptor, 5)
      self.assertRaises(ValueError, controller.get_microdescriptor, 'z' * 30)

      # try with a relay that doesn't exist
      self.assertRaises(stem.ControllerError, controller.get_microdescriptor, 'blargg')
      self.assertRaises(stem.ControllerError, controller.get_microdescriptor, '5' * 40)

      test_relay = self._get_router_status_entry(controller)

      md_by_fingerprint = controller.get_microdescriptor(test_relay.fingerprint)
      md_by_nickname = controller.get_microdescriptor(test_relay.nickname)

      self.assertEqual(md_by_fingerprint, md_by_nickname)

  @require_controller
  def test_get_microdescriptors(self):
    """
    Fetches a few descriptors via the get_microdescriptors() method.
    """

    runner = test.runner.get_runner()

    if not os.path.exists(runner.get_test_dir('cached-descriptors')):
      test.runner.skip(self, '(no cached microdescriptors)')
      return

    with runner.get_tor_controller() as controller:
      count = 0

      for desc in controller.get_microdescriptors():
        self.assertTrue(desc.onion_key is not None)

        count += 1
        if count > 10:
          break

  @require_controller
  def test_get_server_descriptor(self):
    """
    Basic checks for get_server_descriptor().
    """

    runner = test.runner.get_runner()

    if runner.get_tor_version() >= Requirement.MICRODESCRIPTOR_IS_DEFAULT:
      test.runner.skip(self, '(requires server descriptors)')
      return

    with runner.get_tor_controller() as controller:
      # we should balk at invalid content
      self.assertRaises(ValueError, controller.get_server_descriptor, None)
      self.assertRaises(ValueError, controller.get_server_descriptor, '')
      self.assertRaises(ValueError, controller.get_server_descriptor, 5)
      self.assertRaises(ValueError, controller.get_server_descriptor, 'z' * 30)

      # try with a relay that doesn't exist
      self.assertRaises(stem.ControllerError, controller.get_server_descriptor, 'blargg')
      self.assertRaises(stem.ControllerError, controller.get_server_descriptor, '5' * 40)

      test_relay = self._get_router_status_entry(controller)

      desc_by_fingerprint = controller.get_server_descriptor(test_relay.fingerprint)
      desc_by_nickname = controller.get_server_descriptor(test_relay.nickname)

      self.assertEqual(desc_by_fingerprint, desc_by_nickname)

  @require_controller
  def test_get_server_descriptors(self):
    """
    Fetches a few descriptors via the get_server_descriptors() method.
    """

    runner = test.runner.get_runner()

    if runner.get_tor_version() >= Requirement.MICRODESCRIPTOR_IS_DEFAULT:
      test.runner.skip(self, '(requires server descriptors)')
      return

    with runner.get_tor_controller() as controller:
      count = 0

      for desc in controller.get_server_descriptors():
        self.assertTrue(desc.fingerprint is not None)
        self.assertTrue(desc.nickname is not None)

        # Se don't want to take the time to read the whole thing. We already
        # have another test that reads the full cached descriptors (and takes a
        # while to do so).

        count += 1
        if count > 10:
          break

  @require_controller
  @require_online
  def test_get_network_status(self):
    """
    Basic checks for get_network_status().
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      # we should balk at invalid content
      self.assertRaises(ValueError, controller.get_network_status, '')
      self.assertRaises(ValueError, controller.get_network_status, 5)
      self.assertRaises(ValueError, controller.get_network_status, 'z' * 30)

      # try with a relay that doesn't exist
      self.assertRaises(stem.ControllerError, controller.get_network_status, 'blargg')
      self.assertRaises(stem.ControllerError, controller.get_network_status, '5' * 40)

      test_relay = self._get_router_status_entry(controller)

      desc_by_fingerprint = controller.get_network_status(test_relay.fingerprint)
      desc_by_nickname = controller.get_network_status(test_relay.nickname)

      self.assertEqual(desc_by_fingerprint, desc_by_nickname)

  @require_controller
  @require_online
  def test_get_network_statuses(self):
    """
    Fetches a few descriptors via the get_network_statuses() method.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      count = 0

      for desc in controller.get_network_statuses():
        self.assertTrue(desc.fingerprint is not None)
        self.assertTrue(desc.nickname is not None)

        for line in desc.get_unrecognized_lines():
          register_new_capability('Consensus Line', line)

        count += 1
        if count > 10:
          break

  @require_controller
  @require_online
  @require_version(Requirement.HSFETCH)
  def test_get_hidden_service_descriptor(self):
    """
    Fetches a few descriptors via the get_hidden_service_descriptor() method.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_controller() as controller:
      # fetch the descriptor for DuckDuckGo

      desc = controller.get_hidden_service_descriptor('3g2upl4pq6kufc4m.onion')
      self.assertTrue('MIGJAoGBAJ' in desc.permanent_key)

      # try to fetch something that doesn't exist

      try:
        desc = controller.get_hidden_service_descriptor('m4cfuk6qp4lpu2g3')
        self.fail("Didn't expect m4cfuk6qp4lpu2g3.onion to exist, but provided: %s" % desc)
      except stem.DescriptorUnavailable as exc:
        self.assertEqual('No running hidden service at m4cfuk6qp4lpu2g3.onion', str(exc))

      # ... but shouldn't fail if we have a default argument or aren't awaiting the descriptor

      self.assertEqual('pop goes the weasel', controller.get_hidden_service_descriptor('m4cfuk6qp4lpu2g5', 'pop goes the weasel'))
      self.assertEqual(None, controller.get_hidden_service_descriptor('m4cfuk6qp4lpu2g5', await_result = False))

  @require_controller
  @require_online
  @require_version(Requirement.EXTENDCIRCUIT_PATH_OPTIONAL)
  def test_attachstream(self):
    host = socket.gethostbyname('www.torproject.org')
    port = 80

    circuit_id, streams = None, []

    def handle_streamcreated(stream):
      if stream.status == 'NEW' and circuit_id:
        controller.attach_stream(stream.id, circuit_id)

    with test.runner.get_runner().get_tor_controller() as controller:
      # try 10 times to build a circuit we can connect through
      for i in range(10):
        controller.add_event_listener(handle_streamcreated, stem.control.EventType.STREAM)
        controller.set_conf('__LeaveStreamsUnattached', '1')

        try:
          circuit_id = controller.new_circuit(await_build = True)
          socks_listener = controller.get_socks_listeners()[0]

          with test.network.Socks(socks_listener) as s:
            s.settimeout(30)
            s.connect((host, port))
            streams = controller.get_streams()
            break
        except (stem.CircuitExtensionFailed, socket.timeout):
          continue
        finally:
          controller.remove_event_listener(handle_streamcreated)
          controller.reset_conf('__LeaveStreamsUnattached')

    our_stream = [stream for stream in streams if stream.target_address == host][0]

    self.assertTrue(our_stream.circ_id)
    self.assertTrue(circuit_id)

    self.assertEqual(our_stream.circ_id, circuit_id)

  @require_controller
  @require_online
  @require_version(Requirement.EXTENDCIRCUIT_PATH_OPTIONAL)
  def test_get_circuits(self):
    """
    Fetches circuits via the get_circuits() method.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      new_circ = controller.new_circuit()
      circuits = controller.get_circuits()
      self.assertTrue(new_circ in [circ.id for circ in circuits])

  @require_controller
  def test_transition_to_relay(self):
    """
    Transitions Tor to turn into a relay, then back to a client. This helps to
    catch transition issues such as the one cited in :trac:`14901`.
    """

    with test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual(None, controller.get_conf('OrPort'))

      # DisableNetwork ensures no port is actually opened
      controller.set_options({'OrPort': '9090', 'DisableNetwork': '1'})

      # TODO once tor 0.2.7.x exists, test that we can generate a descriptor on demand.

      self.assertEqual('9090', controller.get_conf('OrPort'))
      controller.reset_conf('OrPort', 'DisableNetwork')
      self.assertEqual(None, controller.get_conf('OrPort'))

  def _get_router_status_entry(self, controller):
    """
    Provides a router status entry for a relay with a nickname other than
    'Unnamed'. This fails the test if unable to find one.
    """

    global TEST_ROUTER_STATUS_ENTRY

    if TEST_ROUTER_STATUS_ENTRY is None:
      for desc in controller.get_network_statuses():
        if desc.nickname != 'Unnamed' and Flag.NAMED in desc.flags:
          TEST_ROUTER_STATUS_ENTRY = desc
          break

      if TEST_ROUTER_STATUS_ENTRY is None:
        # this is only likely to occure if we can't get descriptors
        test.runner.skip(self, '(no named relays)')
        return

    return TEST_ROUTER_STATUS_ENTRY
