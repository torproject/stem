"""
Integration tests for the stem.control.Controller class.
"""

import asyncio
import os
import shutil
import socket
import tempfile
import threading
import time
import unittest

import stem.connection
import stem.control
import stem.descriptor.router_status_entry
import stem.directory
import stem.response.protocolinfo
import stem.socket
import stem.util.str_tools
import stem.version
import test
import test.network
import test.require
import test.runner

from stem import Flag, Signal
from stem.control import EventType, Listener, State
from stem.exit_policy import ExitPolicy
from stem.util.test_tools import async_test

SERVICE_ID = 'yvhz3ofkv7gwf5hpzqvhonpr3gbax2cc7dee3xcnt7dmtlx2gu7vyvid'
PRIVATE_KEY = 'FCV0c0ELDKKDpSFgVIB8Yow8Evj5iD+GoiTtK878NkQ='

# Router status entry for a relay with a nickname other than 'Unnamed'. This is
# used for a few tests that need to look up a relay.

TEST_ROUTER_STATUS_ENTRY = None


class TestController(unittest.TestCase):
  @test.require.only_run_once
  @test.require.controller
  @async_test
  async def test_missing_capabilities(self):
    """
    Check to see if tor supports any events, signals, or features that we
    don't.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      for event in (await controller.get_info('events/names')).split():
        if event not in EventType:
          test.register_new_capability('Event', event)

      for signal in (await controller.get_info('signal/names')).split():
        if signal not in Signal:
          test.register_new_capability('Signal', signal)

      # new features should simply be added to enable_feature()'s docs

      for feature in (await controller.get_info('features/names')).split():
        if feature not in ('EXTENDED_EVENTS', 'VERBOSE_NAMES'):
          test.register_new_capability('Feature', feature)

  def test_from_port(self):
    """
    Basic sanity check for the from_port constructor.
    """

    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      with stem.control.Controller.from_port(port = test.runner.CONTROL_PORT) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      with self.assertRaises(stem.SocketError):
        with stem.control.Controller.from_port(port = test.runner.CONTROL_PORT) as controller:
          pass

  def test_from_socket_file(self):
    """
    Basic sanity check for the from_socket_file constructor.
    """

    if test.runner.Torrc.SOCKET in test.runner.get_runner().get_options():
      with stem.control.Controller.from_socket_file(path = test.runner.CONTROL_SOCKET_PATH) as controller:
        self.assertTrue(isinstance(controller, stem.control.Controller))
    else:
      with self.assertRaises(stem.SocketError):
        with stem.control.Controller.from_socket_file(path = test.runner.CONTROL_SOCKET_PATH) as controller:
          pass

  @test.require.controller
  @async_test
  async def test_reset_notification(self):
    """
    Checks that a notificiation listener is... well, notified of SIGHUPs.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      received_events = []

      def status_listener(my_controller, state, timestamp):
        received_events.append((my_controller, state, timestamp))

      controller.add_status_listener(status_listener)

      before = time.time()
      await controller.signal(Signal.HUP)

      # I really hate adding a sleep here, but signal() is non-blocking.
      while len(received_events) == 0:
        if (time.time() - before) > 2:
          self.fail("We've waited a couple seconds for SIGHUP to generate an event, but it didn't come")

        await asyncio.sleep(0.001)

      after = time.time()

      self.assertEqual(1, len(received_events))

      state_controller, state_type, state_timestamp = received_events[0]

      self.assertEqual(controller, state_controller)
      self.assertEqual(State.RESET, state_type)
      self.assertTrue(state_timestamp > before and state_timestamp < after)

      await controller.reset_conf('__OwningControllerProcess')

  @test.require.controller
  @async_test
  async def test_event_handling(self):
    """
    Add a couple listeners for various events and make sure that they receive
    them. Then remove the listeners.
    """

    event_notice1, event_notice2 = asyncio.Event(), asyncio.Event()
    event_buffer1, event_buffer2 = [], []

    def listener1(event):
      event_buffer1.append(event)
      event_notice1.set()

    def listener2(event):
      event_buffer2.append(event)
      event_notice2.set()

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      await controller.add_event_listener(listener1, EventType.CONF_CHANGED)
      await controller.add_event_listener(listener2, EventType.CONF_CHANGED, EventType.DEBUG)

      # The NodeFamily is a harmless option we can toggle
      await controller.set_conf('NodeFamily', 'FD4CC275C5AA4D27A487C6CA29097900F85E2C33')

      # Wait for the event. Assert that we get it within 10 seconds
      await asyncio.wait_for(event_notice1.wait(), timeout = 10)
      self.assertEqual(len(event_buffer1), 1)
      event_notice1.clear()

      await asyncio.wait_for(event_notice2.wait(), timeout = 10)
      self.assertTrue(len(event_buffer2) >= 1)
      event_notice2.clear()

      # Checking that a listener's no longer called after being removed.

      await controller.remove_event_listener(listener2)

      buffer2_size = len(event_buffer2)

      await controller.set_conf('NodeFamily', 'A82F7EFDB570F6BC801805D0328D30A99403C401')
      await asyncio.wait_for(event_notice1.wait(), timeout = 10)
      self.assertEqual(len(event_buffer1), 2)
      event_notice1.clear()

      self.assertEqual(buffer2_size, len(event_buffer2))

      for event in event_buffer1:
        self.assertTrue(isinstance(event, stem.response.events.Event))
        self.assertEqual(0, len(event.positional_args))
        self.assertEqual({}, event.keyword_args)

        self.assertTrue(isinstance(event, stem.response.events.ConfChangedEvent))

      await controller.reset_conf('NodeFamily')

  @test.require.controller
  @async_test
  async def test_reattaching_listeners(self):
    """
    Checks that event listeners are re-attached when a controller disconnects
    then reconnects to tor.
    """

    event_notice = asyncio.Event()
    event_buffer = []

    def listener(event):
      event_buffer.append(event)
      event_notice.set()

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      await controller.add_event_listener(listener, EventType.CONF_CHANGED)

      # trigger an event

      await controller.set_conf('NodeFamily', 'FD4CC275C5AA4D27A487C6CA29097900F85E2C33')
      await asyncio.wait_for(event_notice.wait(), timeout = 4)
      self.assertTrue(len(event_buffer) >= 1)

      # disconnect, then reconnect and check that we get events again

      await controller.close()
      event_notice.clear()
      event_buffer = []

      await controller.connect()
      await controller.authenticate(password = test.runner.CONTROL_PASSWORD)
      self.assertTrue(len(event_buffer) == 0)
      await controller.set_conf('NodeFamily', 'A82F7EFDB570F6BC801805D0328D30A99403C401')

      await asyncio.wait_for(event_notice.wait(), timeout = 4)
      self.assertTrue(len(event_buffer) >= 1)

      await controller.reset_conf('NodeFamily')

  @test.require.controller
  @async_test
  async def test_getinfo(self):
    """
    Exercises GETINFO with valid and invalid queries.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # successful single query

      torrc_path = runner.get_torrc_path()
      self.assertEqual(torrc_path, await controller.get_info('config-file'))
      self.assertEqual(torrc_path, await controller.get_info('config-file', 'ho hum'))

      expected = {'config-file': torrc_path}
      self.assertEqual(expected, await controller.get_info(['config-file']))
      self.assertEqual(expected, await controller.get_info(['config-file'], 'ho hum'))

      # successful batch query, we don't know the values so just checking for
      # the keys

      getinfo_params = set(['version', 'config-file', 'config/names'])
      self.assertEqual(getinfo_params, set((await controller.get_info(['version', 'config-file', 'config/names'])).keys()))

      # non-existant option

      with self.assertRaises(stem.ControllerError):
        await controller.get_info('blarg')

      self.assertEqual('ho hum', await controller.get_info('blarg', 'ho hum'))

      # empty input

      with self.assertRaises(stem.ControllerError):
        await controller.get_info('')

      self.assertEqual('ho hum', await controller.get_info('', 'ho hum'))

      self.assertEqual({}, await controller.get_info([]))
      self.assertEqual({}, await controller.get_info([], {}))

  @test.require.controller
  @async_test
  async def test_getinfo_freshrelaydescs(self):
    """
    Exercises 'GETINFO status/fresh-relay-descs'.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      response = await controller.get_info('status/fresh-relay-descs')
      div = response.find('\nextra-info ')
      nickname = await controller.get_conf('Nickname')

      if div == -1:
        self.fail('GETINFO response should have both a server and extrainfo descriptor:\n%s' % response)

      server_desc = stem.descriptor.server_descriptor.ServerDescriptor(response[:div], validate = True)
      extrainfo_desc = stem.descriptor.extrainfo_descriptor.ExtraInfoDescriptor(response[div:], validate = True)

      self.assertEqual(nickname, server_desc.nickname)
      self.assertEqual(nickname, extrainfo_desc.nickname)
      self.assertEqual(await controller.get_info('address'), server_desc.address)
      self.assertEqual(test.runner.ORPORT, server_desc.or_port)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_getinfo_dir_status(self):
    """
    Exercise 'GETINFO dir/status-vote/*'.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      consensus = await controller.get_info('dir/status-vote/current/consensus')
      self.assertTrue('moria1' in consensus, 'moria1 not found in the consensus')

      if test.tor_version() >= stem.version.Version('0.4.3.1-alpha'):
        microdescs = await controller.get_info('dir/status-vote/current/consensus-microdesc')
        self.assertTrue('moria1' in microdescs, 'moria1 not found in the microdescriptor consensus')

  @test.require.controller
  @async_test
  async def test_get_version(self):
    """
    Test that the convenient method get_version() works.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      version = await controller.get_version()
      self.assertTrue(isinstance(version, stem.version.Version))
      self.assertEqual(version, test.tor_version())

  @test.require.controller
  @async_test
  async def test_get_exit_policy(self):
    """
    Sanity test for get_exit_policy(). Our 'ExitRelay 0' torrc entry causes us
    to have a simple reject-all policy.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual(ExitPolicy('reject *:*'), await controller.get_exit_policy())

  @test.require.controller
  @async_test
  async def test_authenticate(self):
    """
    Test that the convenient method authenticate() works.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller(False) as controller:
      await controller.authenticate(test.runner.CONTROL_PASSWORD)
      await test.runner.exercise_controller(self, controller)

  @test.require.controller
  @async_test
  async def test_protocolinfo(self):
    """
    Test that the convenient method protocolinfo() works.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller(False) as controller:
      protocolinfo = await controller.get_protocolinfo()
      self.assertTrue(isinstance(protocolinfo, stem.response.protocolinfo.ProtocolInfoResponse))

      # Doing a sanity test on the ProtocolInfoResponse instance returned.
      tor_options = runner.get_options()
      auth_methods = []

      if test.runner.Torrc.COOKIE in tor_options:
        auth_methods.append(stem.connection.AuthMethod.COOKIE)
        auth_methods.append(stem.connection.AuthMethod.SAFECOOKIE)

      if test.runner.Torrc.PASSWORD in tor_options:
        auth_methods.append(stem.connection.AuthMethod.PASSWORD)

      if not auth_methods:
        auth_methods.append(stem.connection.AuthMethod.NONE)

      self.assertEqual(tuple(auth_methods), protocolinfo.auth_methods)

  @test.require.controller
  @async_test
  async def test_getconf(self):
    """
    Exercises GETCONF with valid and invalid queries.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      control_socket = controller.get_socket()

      if isinstance(control_socket, stem.socket.ControlPort):
        connection_value = str(control_socket.port)
        config_key = 'ControlPort'
      elif isinstance(control_socket, stem.socket.ControlSocketFile):
        connection_value = control_socket.path
        config_key = 'ControlSocket'

      # successful single query
      self.assertEqual(connection_value, await controller.get_conf(config_key))
      self.assertEqual(connection_value, await controller.get_conf(config_key, 'la-di-dah'))

      # succeessful batch query
      expected = {config_key: [connection_value]}
      self.assertEqual(expected, await controller.get_conf_map([config_key]))
      self.assertEqual(expected, await controller.get_conf_map([config_key], 'la-di-dah'))

      request_params = ['ControlPORT', 'dirport', 'datadirectory']
      reply_params = (await controller.get_conf_map(request_params, multiple=False)).keys()
      self.assertEqual(set(request_params), set(reply_params))

      # queries an option that is unset

      self.assertEqual(None, await controller.get_conf('HTTPSProxy'))
      self.assertEqual('la-di-dah', await controller.get_conf('HTTPSProxy', 'la-di-dah'))
      self.assertEqual([], await controller.get_conf('HTTPSProxy', [], multiple = True))

      # non-existant option(s)

      with self.assertRaises(stem.InvalidArguments):
        await controller.get_conf('blarg')

      self.assertEqual('la-di-dah', await controller.get_conf('blarg', 'la-di-dah'))

      with self.assertRaises(stem.InvalidArguments):
        await controller.get_conf_map('blarg')

      self.assertEqual({'blarg': 'la-di-dah'}, await controller.get_conf_map('blarg', 'la-di-dah'))

      with self.assertRaises(stem.InvalidRequest):
        await controller.get_conf_map(['blarg', 'huadf'], multiple = True)

      self.assertEqual({'erfusdj': 'la-di-dah', 'afiafj': 'la-di-dah'}, await controller.get_conf_map(['erfusdj', 'afiafj'], 'la-di-dah', multiple = True))

      # multivalue configuration keys
      nodefamilies = [('abc', 'xyz', 'pqrs'), ('mno', 'tuv', 'wxyz')]
      await controller.msg('SETCONF %s' % ' '.join(['nodefamily="' + ','.join(x) + '"' for x in nodefamilies]))
      self.assertEqual([','.join(n) for n in nodefamilies], await controller.get_conf('nodefamily', multiple = True))
      await controller.msg('RESETCONF NodeFamily')

      # empty input
      self.assertEqual(None, await controller.get_conf(''))
      self.assertEqual({}, await controller.get_conf_map([]))
      self.assertEqual({}, await controller.get_conf_map(['']))
      self.assertEqual(None, await controller.get_conf('          '))
      self.assertEqual({}, await controller.get_conf_map(['    ', '        ']))

      self.assertEqual('la-di-dah', await controller.get_conf('', 'la-di-dah'))
      self.assertEqual({}, await controller.get_conf_map('', 'la-di-dah'))
      self.assertEqual({}, await controller.get_conf_map([], 'la-di-dah'))

  @test.require.controller
  @async_test
  async def test_is_set(self):
    """
    Exercises our is_set() method.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      custom_options = await controller._get_custom_options()
      self.assertTrue('ControlPort' in custom_options or 'ControlSocket' in custom_options)
      self.assertEqual('1', custom_options['DownloadExtraInfo'])
      self.assertEqual('1112', custom_options['SocksPort'])

      self.assertTrue(await controller.is_set('DownloadExtraInfo'))
      self.assertTrue(await controller.is_set('SocksPort'))
      self.assertFalse(await controller.is_set('CellStatistics'))
      self.assertFalse(await controller.is_set('ConnLimit'))

      # check we update when setting and resetting values

      await controller.set_conf('ConnLimit', '1005')
      self.assertTrue(await controller.is_set('ConnLimit'))

      await controller.reset_conf('ConnLimit')
      self.assertFalse(await controller.is_set('ConnLimit'))

  @test.require.controller
  @async_test
  async def test_hidden_services_conf(self):
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

    async with await runner.get_tor_controller() as controller:
      try:
        # initially we shouldn't be running any hidden services

        self.assertEqual({}, await controller.get_hidden_service_conf())

        # try setting a blank config, shouldn't have any impact

        await controller.set_hidden_service_conf({})
        self.assertEqual({}, await controller.get_hidden_service_conf())

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
            'HiddenServiceVersion': '2',
            'HiddenServiceAuthorizeClient': 'stealth a, b',
            'HiddenServicePort': [
              (8030, '127.0.0.1', 8030),
              (8031, '127.0.0.1', 8031),
              (8032, '127.0.0.1', 8032),
            ]
          },
        }

        await controller.set_hidden_service_conf(initialconf)
        self.assertEqual(initialconf, await controller.get_hidden_service_conf())

        # add already existing services, with/without explicit target

        self.assertEqual(None, await controller.create_hidden_service(service1_path, 8020))
        self.assertEqual(None, await controller.create_hidden_service(service1_path, 8021, target_port = 8021))
        self.assertEqual(initialconf, await controller.get_hidden_service_conf())

        # add a new service, with/without explicit target

        hs_path = os.path.join(os.getcwd(), service3_path)
        hs_address1 = (await controller.create_hidden_service(hs_path, 8888)).hostname
        hs_address2 = (await controller.create_hidden_service(hs_path, 8989, target_port = 8021)).hostname

        self.assertEqual(hs_address1, hs_address2)
        self.assertTrue(hs_address1.endswith('.onion'))

        conf = await controller.get_hidden_service_conf()
        self.assertEqual(3, len(conf))
        self.assertEqual(2, len(conf[hs_path]['HiddenServicePort']))

        # remove a hidden service, the service dir should still be there

        await controller.remove_hidden_service(hs_path, 8888)
        self.assertEqual(3, len(await controller.get_hidden_service_conf()))

        # remove a service completely, it should now be gone

        await controller.remove_hidden_service(hs_path, 8989)
        self.assertEqual(2, len(await controller.get_hidden_service_conf()))

        # add a new service, this time with client authentication

        hs_path = os.path.join(os.getcwd(), service4_path)
        hs_attributes = await controller.create_hidden_service(hs_path, 8888, auth_type = 'basic', client_names = ['c1', 'c2'])

        self.assertEqual(2, len(hs_attributes.hostname.splitlines()))
        self.assertEqual(2, len(hs_attributes.hostname_for_client))
        self.assertTrue(hs_attributes.hostname_for_client['c1'].endswith('.onion'))
        self.assertTrue(hs_attributes.hostname_for_client['c2'].endswith('.onion'))

        conf = await controller.get_hidden_service_conf()
        self.assertEqual(3, len(conf))
        self.assertEqual(1, len(conf[hs_path]['HiddenServicePort']))

        # remove a hidden service

        await controller.remove_hidden_service(hs_path, 8888)
        self.assertEqual(2, len(await controller.get_hidden_service_conf()))
      finally:
        await controller.set_hidden_service_conf({})  # drop hidden services created during the test

        # clean up the hidden service directories created as part of this test

        for path in (service1_path, service2_path, service3_path, service4_path):
          try:
            shutil.rmtree(path)
          except:
            pass

  @test.require.controller
  @async_test
  async def test_without_ephemeral_hidden_services(self):
    """
    Exercises ephemeral hidden service methods when none are present.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual([], await controller.list_ephemeral_hidden_services())
      self.assertEqual([], await controller.list_ephemeral_hidden_services(detached = True))
      self.assertEqual(False, await controller.remove_ephemeral_hidden_service('gfzprpioee3hoppz'))

  @test.require.controller
  @async_test
  async def test_with_invalid_ephemeral_hidden_service_port(self):
    async with await test.runner.get_runner().get_tor_controller() as controller:
      for ports in (4567890, [4567, 4567890], {4567: '-:4567'}):
        with self.assertRaisesWith(stem.ProtocolError, "ADD_ONION response didn't have an OK status: Invalid VIRTPORT/TARGET"):
          await controller.create_ephemeral_hidden_service(ports)

  @test.require.controller
  @async_test
  async def test_ephemeral_hidden_services_v2(self):
    """
    Exercises creating v2 ephemeral hidden services.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      response = await controller.create_ephemeral_hidden_service(4567, key_content = 'RSA1024')
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services())
      self.assertTrue(response.private_key is not None)
      self.assertEqual('RSA1024', response.private_key_type)
      self.assertEqual({}, response.client_auth)

      # drop the service

      self.assertEqual(True, await controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], await controller.list_ephemeral_hidden_services())

      # recreate the service with the same private key

      recreate_response = await controller.create_ephemeral_hidden_service(4567, key_type = response.private_key_type, key_content = response.private_key)
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services())
      self.assertEqual(response.service_id, recreate_response.service_id)

      # the response only includes the private key when making a new one

      self.assertEqual(None, recreate_response.private_key)
      self.assertEqual(None, recreate_response.private_key_type)

      # create a service where we never see the private key

      response = await controller.create_ephemeral_hidden_service(4568, key_content = 'RSA1024', discard_key = True)
      self.assertTrue(response.service_id in await controller.list_ephemeral_hidden_services())
      self.assertEqual(None, response.private_key)
      self.assertEqual(None, response.private_key_type)

      # other controllers shouldn't be able to see these hidden services

      async with await runner.get_tor_controller() as second_controller:
        self.assertEqual(2, len(await controller.list_ephemeral_hidden_services()))
        self.assertEqual(0, len(await second_controller.list_ephemeral_hidden_services()))

  @test.require.controller
  @async_test
  async def test_ephemeral_hidden_services_v3(self):
    """
    Exercises creating v3 ephemeral hidden services.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      response = await controller.create_ephemeral_hidden_service(4567, key_content = 'ED25519-V3')
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services())
      self.assertTrue(response.private_key is not None)
      self.assertEqual('ED25519-V3', response.private_key_type)
      self.assertEqual({}, response.client_auth)

      # drop the service

      self.assertEqual(True, await controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], await controller.list_ephemeral_hidden_services())

      # recreate the service with the same private key

      recreate_response = await controller.create_ephemeral_hidden_service(4567, key_type = response.private_key_type, key_content = response.private_key)
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services())
      self.assertEqual(response.service_id, recreate_response.service_id)

      # the response only includes the private key when making a new one

      self.assertEqual(None, recreate_response.private_key)
      self.assertEqual(None, recreate_response.private_key_type)

      # create a service where we never see the private key

      response = await controller.create_ephemeral_hidden_service(4568, key_content = 'ED25519-V3', discard_key = True)
      self.assertTrue(response.service_id in await controller.list_ephemeral_hidden_services())
      self.assertEqual(None, response.private_key)
      self.assertEqual(None, response.private_key_type)

      # other controllers shouldn't be able to see these hidden services

      async with await runner.get_tor_controller() as second_controller:
        self.assertEqual(2, len(await controller.list_ephemeral_hidden_services()))
        self.assertEqual(0, len(await second_controller.list_ephemeral_hidden_services()))

  @test.require.controller
  @async_test
  async def test_with_ephemeral_hidden_services_basic_auth(self):
    """
    Exercises creating ephemeral hidden services that uses basic authentication.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      response = await controller.create_ephemeral_hidden_service(4567, key_content = 'RSA1024', basic_auth = {'alice': 'nKwfvVPmTNr2k2pG0pzV4g', 'bob': None})
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services())
      self.assertTrue(response.private_key is not None)
      self.assertEqual(['bob'], list(response.client_auth.keys()))  # newly created credentials were only created for bob

      # drop the service

      self.assertEqual(True, await controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], await controller.list_ephemeral_hidden_services())

  @test.require.controller
  @async_test
  async def test_with_ephemeral_hidden_services_basic_auth_no_credentials(self):
    """
    Exercises creating ephemeral hidden services when attempting to use basic
    auth but not including any credentials.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      with self.assertRaisesWith(stem.ProtocolError, "ADD_ONION response didn't have an OK status: No auth clients specified"):
        await controller.create_ephemeral_hidden_service(4567, basic_auth = {})

  @test.require.controller
  @async_test
  async def test_with_detached_ephemeral_hidden_services(self):
    """
    Exercises creating detached ephemeral hidden services and methods when
    they're present.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      response = await controller.create_ephemeral_hidden_service(4567, detached = True)
      self.assertEqual([], await controller.list_ephemeral_hidden_services())
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services(detached = True))

      # drop and recreate the service

      self.assertEqual(True, await controller.remove_ephemeral_hidden_service(response.service_id))
      self.assertEqual([], await controller.list_ephemeral_hidden_services(detached = True))
      await controller.create_ephemeral_hidden_service(4567, key_type = response.private_key_type, key_content = response.private_key, detached = True)
      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services(detached = True))

      # other controllers should be able to see this service, and drop it

      async with await runner.get_tor_controller() as second_controller:
        self.assertEqual([response.service_id], await second_controller.list_ephemeral_hidden_services(detached = True))
        self.assertEqual(True, await second_controller.remove_ephemeral_hidden_service(response.service_id))
        self.assertEqual([], await controller.list_ephemeral_hidden_services(detached = True))

        # recreate the service and confirms that it outlives this controller

        response = await second_controller.create_ephemeral_hidden_service(4567, detached = True)

      self.assertEqual([response.service_id], await controller.list_ephemeral_hidden_services(detached = True))
      await controller.remove_ephemeral_hidden_service(response.service_id)

  @test.require.controller
  @async_test
  async def test_rejecting_unanonymous_hidden_services_creation(self):
    """
    Attempt to create a non-anonymous hidden service despite not setting
    HiddenServiceSingleHopMode and HiddenServiceNonAnonymousMode.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      self.assertEqual('Tor is in anonymous hidden service mode', str(await controller.msg('ADD_ONION NEW:BEST Flags=NonAnonymous Port=4567')))

  @test.require.controller
  @async_test
  async def test_set_conf(self):
    """
    Exercises set_conf(), reset_conf(), and set_options() methods with valid
    and invalid requests.
    """

    runner = test.runner.get_runner()

    with tempfile.TemporaryDirectory() as tmpdir:

      async with await runner.get_tor_controller() as controller:
        try:
          # successfully set a single option
          connlimit = int(await controller.get_conf('ConnLimit'))
          await controller.set_conf('connlimit', str(connlimit - 1))
          self.assertEqual(connlimit - 1, int(await controller.get_conf('ConnLimit')))

          # successfully set a single list option
          exit_policy = ['accept *:7777', 'reject *:*']
          await controller.set_conf('ExitPolicy', exit_policy)
          self.assertEqual(exit_policy, await controller.get_conf('ExitPolicy', multiple = True))

          # fail to set a single option
          try:
            await controller.set_conf('invalidkeyboo', 'abcde')
            self.fail()
          except stem.InvalidArguments as exc:
            self.assertEqual(['invalidkeyboo'], exc.arguments)

          # resets configuration parameters
          await controller.reset_conf('ConnLimit', 'ExitPolicy')
          self.assertEqual(connlimit, int(await controller.get_conf('ConnLimit')))
          self.assertEqual(None, await controller.get_conf('ExitPolicy'))

          # successfully sets multiple config options
          await controller.set_options({
            'connlimit': str(connlimit - 2),
            'contactinfo': 'stem@testing',
          })

          self.assertEqual(connlimit - 2, int(await controller.get_conf('ConnLimit')))
          self.assertEqual('stem@testing', await controller.get_conf('contactinfo'))

          # fail to set multiple config options
          try:
            await controller.set_options({
              'contactinfo': 'stem@testing',
              'bombay': 'vadapav',
            })
            self.fail()
          except stem.InvalidArguments as exc:
            self.assertEqual(['bombay'], exc.arguments)

          # context-sensitive keys (the only retched things for which order matters)
          await controller.set_options((
            ('HiddenServiceDir', tmpdir),
            ('HiddenServicePort', '17234 127.0.0.1:17235'),
          ))

          self.assertEqual(tmpdir, await controller.get_conf('HiddenServiceDir'))
          self.assertEqual('17234 127.0.0.1:17235', await controller.get_conf('HiddenServicePort'))
        finally:
          # reverts configuration changes

          await controller.set_options((
            ('ExitPolicy', 'reject *:*'),
            ('ConnLimit', None),
            ('ContactInfo', None),
            ('HiddenServiceDir', None),
            ('HiddenServicePort', None),
          ), reset = True)

  @test.require.controller
  @async_test
  async def test_set_conf_for_usebridges(self):
    """
    Ensure we can set UseBridges=1 and also set a Bridge. This is a tor
    regression check.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      orport = await controller.get_conf('ORPort')

      try:
        await controller.set_conf('ORPort', '0')  # ensure we're not a relay so UseBridges is usabe
        await controller.set_options([('UseBridges', '1'), ('Bridge', '127.0.0.1:9999')])
        self.assertEqual('127.0.0.1:9999', await controller.get_conf('Bridge'))
      finally:
        # reverts configuration changes

        await controller.set_options((
          ('ORPort', orport),
          ('UseBridges', None),
          ('Bridge', None),
        ), reset = True)

  @test.require.controller
  @async_test
  async def test_set_conf_when_immutable(self):
    """
    Issue a SETCONF for tor options that cannot be changed while running.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      with self.assertRaisesWith(stem.InvalidArguments, "DisableAllSwap cannot be changed while tor's running"):
        await controller.set_conf('DisableAllSwap', '1')

      with self.assertRaisesWith(stem.InvalidArguments, "DisableAllSwap, User cannot be changed while tor's running"):
        await controller.set_options({'User': 'atagar', 'DisableAllSwap': '1'})

  @test.require.controller
  @async_test
  async def test_loadconf(self):
    """
    Exercises Controller.load_conf with valid and invalid requests.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      oldconf = runner.get_torrc_contents()

      try:
        # Check a request that changes our DataDir. Tor should rightfully balk
        # at this...
        #
        #   InvalidRequest: Transition not allowed: Failed to parse/validate
        #   config: While Tor is running, changing DataDirectory
        #   ("/home/atagar/Desktop/stem/test/data"->"/home/atagar/.tor") is not
        #   allowed.

        with self.assertRaises(stem.InvalidRequest):
          await controller.load_conf('ContactInfo confloaded')

        try:
          await controller.load_conf('Blahblah blah')
          self.fail()
        except stem.InvalidArguments as exc:
          self.assertEqual(['Blahblah'], exc.arguments)

        # valid config

        await controller.load_conf(runner.get_torrc_contents() + '\nContactInfo confloaded\n')
        self.assertEqual('confloaded', await controller.get_conf('ContactInfo'))
      finally:
        # reload original valid config
        await controller.load_conf(oldconf)
        await controller.reset_conf('__OwningControllerProcess')

  @test.require.controller
  @async_test
  async def test_saveconf(self):
    runner = test.runner.get_runner()

    # only testing for success, since we need to run out of disk space to test
    # for failure
    async with await runner.get_tor_controller() as controller:
      oldconf = runner.get_torrc_contents()

      try:
        await controller.set_conf('ContactInfo', 'confsaved')
        await controller.save_conf()

        with open(runner.get_torrc_path()) as torrcfile:
          self.assertTrue('\nContactInfo confsaved\n' in torrcfile.read())
      finally:
        await controller.load_conf(oldconf)
        await controller.save_conf()
        await controller.reset_conf('__OwningControllerProcess')

  @test.require.controller
  @async_test
  async def test_get_ports(self):
    """
    Test Controller.get_ports against a running tor instance.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      self.assertEqual(set([test.runner.ORPORT]), await controller.get_ports(Listener.OR))
      self.assertEqual(set(), await controller.get_ports(Listener.DIR))
      self.assertEqual(set([test.runner.SOCKS_PORT]), await controller.get_ports(Listener.SOCKS))
      self.assertEqual(set(), await controller.get_ports(Listener.TRANS))
      self.assertEqual(set(), await controller.get_ports(Listener.NATD))
      self.assertEqual(set(), await controller.get_ports(Listener.DNS))

      if test.runner.Torrc.PORT in runner.get_options():
        self.assertEqual(set([test.runner.CONTROL_PORT]), await controller.get_ports(Listener.CONTROL))
      else:
        self.assertEqual(set(), await controller.get_ports(Listener.CONTROL))

  @test.require.controller
  @async_test
  async def test_get_listeners(self):
    """
    Test Controller.get_listeners against a running tor instance.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      if test.tor_version() >= stem.version.Version('0.4.5.0'):
        expected_orports = [('0.0.0.0', test.runner.ORPORT), ('::', test.runner.ORPORT)]
      else:
        expected_orports = [('0.0.0.0', test.runner.ORPORT)]

      self.assertEqual(expected_orports, await controller.get_listeners(Listener.OR))
      self.assertEqual([], await controller.get_listeners(Listener.DIR))
      self.assertEqual([('127.0.0.1', test.runner.SOCKS_PORT)], await controller.get_listeners(Listener.SOCKS))
      self.assertEqual([], await controller.get_listeners(Listener.TRANS))
      self.assertEqual([], await controller.get_listeners(Listener.NATD))
      self.assertEqual([], await controller.get_listeners(Listener.DNS))

      if test.runner.Torrc.PORT in runner.get_options():
        self.assertEqual([('127.0.0.1', test.runner.CONTROL_PORT)], await controller.get_listeners(Listener.CONTROL))
      else:
        self.assertEqual([], await controller.get_listeners(Listener.CONTROL))

  @test.require.controller
  @test.require.online
  @test.require.version(stem.version.Version('0.1.2.2-alpha'))
  @async_test
  async def test_enable_feature(self):
    """
    Test Controller.enable_feature with valid and invalid inputs.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      self.assertTrue(controller.is_feature_enabled('VERBOSE_NAMES'))

      with self.assertRaises(stem.InvalidArguments):
        await controller.enable_feature(['NOT', 'A', 'FEATURE'])

      try:
        await controller.enable_feature(['NOT', 'A', 'FEATURE'])
      except stem.InvalidArguments as exc:
        self.assertEqual(['NOT'], exc.arguments)
      else:
        self.fail()

  @test.require.controller
  @async_test
  async def test_signal(self):
    """
    Test controller.signal with valid and invalid signals.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      # valid signal
      await controller.signal('CLEARDNSCACHE')

      # invalid signals

      with self.assertRaises(stem.InvalidArguments):
        await controller.signal('FOOBAR')

  @test.require.controller
  @async_test
  async def test_newnym_availability(self):
    """
    Test the is_newnym_available and get_newnym_wait methods.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      self.assertEqual(True, controller.is_newnym_available())
      self.assertEqual(0.0, controller.get_newnym_wait())

      await controller.signal(stem.Signal.NEWNYM)

      self.assertEqual(False, controller.is_newnym_available())
      self.assertTrue(controller.get_newnym_wait() > 9.0)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_extendcircuit(self):
    async with await test.runner.get_runner().get_tor_controller() as controller:
      circuit_id = await controller.extend_circuit('0')

      # check if our circuit was created

      self.assertNotEqual(None, await controller.get_circuit(circuit_id, None))
      circuit_id = await controller.new_circuit()
      self.assertNotEqual(None, await controller.get_circuit(circuit_id, None))

      with self.assertRaises(stem.InvalidRequest):
        await controller.extend_circuit('foo')

      with self.assertRaises(stem.InvalidRequest):
        await controller.extend_circuit('0', 'thisroutershouldntexistbecausestemexists!@##$%#')

      with self.assertRaises(stem.InvalidRequest):
        await controller.extend_circuit('0', 'thisroutershouldntexistbecausestemexists!@##$%#', 'foo')

  @test.require.controller
  @test.require.online
  @async_test
  async def test_repurpose_circuit(self):
    """
    Tests Controller.repurpose_circuit with valid and invalid input.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      circ_id = await controller.new_circuit()
      await controller.repurpose_circuit(circ_id, 'CONTROLLER')
      circuit = await controller.get_circuit(circ_id)
      self.assertTrue(circuit.purpose == 'CONTROLLER')

      await controller.repurpose_circuit(circ_id, 'GENERAL')
      circuit = await controller.get_circuit(circ_id)
      self.assertTrue(circuit.purpose == 'GENERAL')

      with self.assertRaises(stem.InvalidRequest):
        await controller.repurpose_circuit('f934h9f3h4', 'fooo')

      with self.assertRaises(stem.InvalidRequest):
        await controller.repurpose_circuit('4', 'fooo')

  @test.require.controller
  @test.require.online
  @async_test
  async def test_close_circuit(self):
    """
    Tests Controller.close_circuit with valid and invalid input.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      circuit_id = await controller.new_circuit()
      await controller.close_circuit(circuit_id)
      circuit_output = await controller.get_info('circuit-status')
      circ = [x.split()[0] for x in circuit_output.splitlines()]
      self.assertFalse(circuit_id in circ)

      circuit_id = await controller.new_circuit()
      await controller.close_circuit(circuit_id, 'IfUnused')
      circuit_output = await controller.get_info('circuit-status')
      circ = [x.split()[0] for x in circuit_output.splitlines()]
      self.assertFalse(circuit_id in circ)

      circuit_id = await controller.new_circuit()

      with self.assertRaises(stem.InvalidArguments):
        await controller.close_circuit(circuit_id + '1024')

      with self.assertRaises(stem.InvalidRequest):
        await controller.close_circuit('')

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_streams(self):
    """
    Tests Controller.get_streams().
    """

    host = socket.gethostbyname('www.torproject.org')
    port = 443

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # we only need one proxy port, so take the first

      socks_listener = (await controller.get_listeners(Listener.SOCKS))[0]

      with test.network.Socks(socks_listener) as s:
        s.settimeout(30)
        s.connect((host, port))
        streams = await controller.get_streams()

    # Because we do not get a stream id when opening a stream,
    #  try to match the target for which we asked a stream.

    self.assertTrue('%s:%s' % (host, port) in [stream.target for stream in streams])

  @test.require.controller
  @test.require.online
  @async_test
  async def test_close_stream(self):
    """
    Tests Controller.close_stream with valid and invalid input.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # use the first socks listener

      socks_listener = (await controller.get_listeners(Listener.SOCKS))[0]

      with test.network.Socks(socks_listener) as s:
        s.settimeout(30)
        s.connect(('www.torproject.org', 443))

        # There's only one stream right now.  Right?

        built_stream = (await controller.get_streams())[0]

        # Make sure we have the stream for which we asked, otherwise
        # the next assertion would be a false positive.

        self.assertTrue(built_stream.id in [stream.id for stream in await controller.get_streams()])

        # Try to close our stream...

        await controller.close_stream(built_stream.id)

        # ... after which the stream should no longer be present.

        self.assertFalse(built_stream.id in [stream.id for stream in await controller.get_streams()])

      # unknown stream

      with self.assertRaises(stem.InvalidArguments):
        await controller.close_stream('blarg')

  @test.require.controller
  @async_test
  async def test_mapaddress(self):
    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # try mapping one element, ensuring results are as expected

      map1 = {'1.2.1.2': 'ifconfig.me'}
      self.assertEqual(map1, (await controller.map_address(map1)).mapped)

      # try mapping two elements, ensuring results are as expected

      map2 = {'1.2.3.4': 'foobar.example.com',
              '1.2.3.5': 'barfuzz.example.com'}

      self.assertEqual(map2, (await controller.map_address(map2)).mapped)

      # try mapping zero elements

      with self.assertRaises(stem.InvalidRequest):
        await controller.map_address({})

      # try a virtual mapping to IPv4, the default virtualaddressrange is 127.192.0.0/10

      map3 = {'0.0.0.0': 'quux'}
      response = await controller.map_address(map3)
      self.assertEquals(len(response), 1)
      addr1, target = list(response.mapped.items())[0]

      self.assertTrue('%s did not start with 127.' % addr1, addr1.startswith('127.'))
      self.assertEquals('quux', target)

      # try a virtual mapping to IPv6, the default IPv6 virtualaddressrange is FE80::/10

      map4 = {'::': 'quibble'}
      response = await controller.map_address(map4)
      self.assertEquals(1, len(response))
      addr2, target = list(response.mapped.items())[0]

      self.assertTrue(addr2.startswith('[fe'), '%s did not start with [fe.' % addr2)
      self.assertEquals('quibble', target)

      async def address_mappings(addr_type):
        response = await controller.get_info(['address-mappings/%s' % addr_type])
        result = {}

        for line in response['address-mappings/%s' % addr_type].splitlines():
          k, v, timeout = line.split()
          result[k] = v

        return result

      # ask for a list of all the address mappings we've added

      self.assertEquals({
        '1.2.1.2': 'ifconfig.me',
        '1.2.3.4': 'foobar.example.com',
        '1.2.3.5': 'barfuzz.example.com',
        addr1: 'quux',
        addr2: 'quibble',
      }, await address_mappings('control'))

      # ask for a list of all the address mappings

      self.assertEquals({
        '1.2.1.2': 'ifconfig.me',
        '1.2.3.4': 'foobar.example.com',
        '1.2.3.5': 'barfuzz.example.com',
        addr1: 'quux',
        addr2: 'quibble',
      }, await address_mappings('all'))

      # Now ask for a list of only the mappings configured with the
      # configuration.  Ours should not be there.

      self.assertEquals({}, await address_mappings('config'))

      # revert these address mappings

      mapped_addresses = (await address_mappings('control')).keys()
      await controller.map_address(dict([(addr, None) for addr in mapped_addresses]))
      self.assertEquals({}, await address_mappings('control'))

  @test.require.controller
  @test.require.online
  @async_test
  async def test_drop_guards(self):
    async with await test.runner.get_runner().get_tor_controller() as controller:
      previous_guards = await controller.get_info('entry-guards')
      started_at = time.time()

      await controller.drop_guards()

      while time.time() < (started_at + 5):
        if previous_guards != await controller.get_info('entry-guards'):
          return  # success

        await asyncio.sleep(0.01)

      self.fail('DROPGUARDS failed to change our guards within five seconds')

  @test.require.controller
  @test.require.version(stem.version.Requirement.DROPTIMEOUTS)
  @async_test
  async def test_drop_guards_with_reset(self):
    async with await test.runner.get_runner().get_tor_controller() as controller:
      events = asyncio.Queue()

      await controller.add_event_listener(lambda event: events.put_nowait(event), stem.control.EventType.BUILDTIMEOUT_SET)
      await controller.drop_guards(reset_timeouts = True)

      try:
        event = await asyncio.wait_for(events.get(), timeout = 5)
      except asyncio.TimeoutError:
        self.fail('DROPTIMEOUTS failed to emit a BUILDTIMEOUT_SET event within five seconds')

      self.assertEqual('RESET', event.set_type)
      self.assertEqual(0, event.total_times)

  @test.require.controller
  @async_test
  async def test_mapaddress_mixed_response(self):
    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # mix a valid and invalid mapping

      response = await controller.map_address({
        '1.2.1.2': 'ifconfig.me',
        'foo': '@@@',
      })

      self.assertEqual({'1.2.1.2': 'ifconfig.me'}, response.mapped)
      self.assertEqual(["syntax error: invalid address '@@@'"], response.failures)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_microdescriptor(self):
    """
    Basic checks for get_microdescriptor().
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      # we should balk at invalid content

      with self.assertRaises(ValueError):
        await controller.get_microdescriptor('')

      with self.assertRaises(ValueError):
        await controller.get_microdescriptor(5)

      with self.assertRaises(ValueError):
        await controller.get_microdescriptor('z' * 30)

      # try with a relay that doesn't exist

      with self.assertRaises(stem.ControllerError):
        await controller.get_microdescriptor('blargg')

      with self.assertRaises(stem.ControllerError):
        await controller.get_microdescriptor('5' * 40)

      test_relay = await self._get_router_status_entry(controller)

      md_by_fingerprint = await controller.get_microdescriptor(test_relay.fingerprint)
      md_by_nickname = await controller.get_microdescriptor(test_relay.nickname)

      self.assertEqual(md_by_fingerprint, md_by_nickname)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_microdescriptors(self):
    """
    Fetches a few descriptors via the get_microdescriptors() method.
    """

    runner = test.runner.get_runner()

    if not os.path.exists(runner.get_test_dir('cached-microdescs')):
      self.skipTest('(no cached microdescriptors)')

    async with await runner.get_tor_controller() as controller:
      count = 0

      async for desc in controller.get_microdescriptors():
        self.assertTrue(desc.onion_key is not None)

        count += 1
        if count > 10:
          break

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_server_descriptor(self):
    """
    Basic checks for get_server_descriptor().
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # we should balk at invalid content

      with self.assertRaises(ValueError):
        await controller.get_server_descriptor('')

      with self.assertRaises(ValueError):
        await controller.get_server_descriptor(5)

      with self.assertRaises(ValueError):
        await controller.get_server_descriptor('z' * 30)

      # try with a relay that doesn't exist

      with self.assertRaises(stem.ControllerError):
        await controller.get_server_descriptor('blargg')

      with self.assertRaises(stem.ControllerError):
        await controller.get_server_descriptor('5' * 40)

      test_relay = await self._get_router_status_entry(controller)

      desc_by_fingerprint = await controller.get_server_descriptor(test_relay.fingerprint)
      desc_by_nickname = await controller.get_server_descriptor(test_relay.nickname)

      self.assertEqual(desc_by_fingerprint, desc_by_nickname)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_server_descriptors(self):
    """
    Fetches a few descriptors via the get_server_descriptors() method.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      count = 0

      async for desc in controller.get_server_descriptors():
        self.assertTrue(desc.fingerprint is not None)
        self.assertTrue(desc.nickname is not None)

        # Se don't want to take the time to read the whole thing. We already
        # have another test that reads the full cached descriptors (and takes a
        # while to do so).

        count += 1

        if count > 10:
          break

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_network_status(self):
    """
    Basic checks for get_network_status().
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      # we should balk at invalid content

      with self.assertRaises(ValueError):
        await controller.get_network_status('')

      with self.assertRaises(ValueError):
        await controller.get_network_status(5)

      with self.assertRaises(ValueError):
        await controller.get_network_status('z' * 30)

      # try with a relay that doesn't exist

      with self.assertRaises(stem.ControllerError):
        await controller.get_network_status('blargg')

      with self.assertRaises(stem.ControllerError):
        await controller.get_network_status('5' * 40)

      test_relay = await self._get_router_status_entry(controller)

      desc_by_fingerprint = await controller.get_network_status(test_relay.fingerprint)
      desc_by_nickname = await controller.get_network_status(test_relay.nickname)

      self.assertEqual(desc_by_fingerprint, desc_by_nickname)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_network_statuses(self):
    """
    Fetches a few descriptors via the get_network_statuses() method.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      count = 0

      async for desc in controller.get_network_statuses():
        self.assertTrue(desc.fingerprint is not None)
        self.assertTrue(desc.nickname is not None)

        for line in desc.get_unrecognized_lines():
          test.register_new_capability('Consensus Line', line)

        count += 1
        if count > 10:
          break

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_hidden_service_descriptor(self):
    """
    Fetches a few descriptors via the get_hidden_service_descriptor() method.
    """

    runner = test.runner.get_runner()

    async with await runner.get_tor_controller() as controller:
      # fetch the descriptor for DuckDuckGo

      desc = await controller.get_hidden_service_descriptor('3g2upl4pq6kufc4m.onion')
      self.assertTrue('MIGJAoGBAJ' in desc.permanent_key)

      # try to fetch something that doesn't exist

      with self.assertRaisesWith(stem.DescriptorUnavailable, 'No running hidden service at m4cfuk6qp4lpu2g3.onion'):
        await controller.get_hidden_service_descriptor('m4cfuk6qp4lpu2g3')

      # ... but shouldn't fail if we have a default argument or aren't awaiting the descriptor

      self.assertEqual('pop goes the weasel', await controller.get_hidden_service_descriptor('m4cfuk6qp4lpu2g5', 'pop goes the weasel'))
      self.assertEqual(None, await controller.get_hidden_service_descriptor('m4cfuk6qp4lpu2g5', await_result = False))

  @test.require.controller
  @test.require.online
  @async_test
  async def test_attachstream(self):
    host = socket.gethostbyname('www.torproject.org')
    port = 80

    circuit_id, streams = None, []
    stream_attached = asyncio.Event()

    async def handle_streamcreated(stream):
      if stream.status == 'NEW' and circuit_id:
        await controller.attach_stream(stream.id, circuit_id)
        stream_attached.set()

    async with await test.runner.get_runner().get_tor_controller() as controller:
      # try 10 times to build a circuit we can connect through

      await controller.add_event_listener(handle_streamcreated, stem.control.EventType.STREAM)
      await controller.set_conf('__LeaveStreamsUnattached', '1')

      try:
        circuit_id = await controller.new_circuit(await_build = True)
        socks_listener = (await controller.get_listeners(Listener.SOCKS))[0]

        with test.network.Socks(socks_listener) as s:
          s.settimeout(5)

          t = threading.Thread(target = s.connect, args = ((host, port),))
          t.start()

          await asyncio.wait_for(stream_attached.wait(), timeout = 6)
          streams = await controller.get_streams()

          t.join()
      finally:
        await controller.remove_event_listener(handle_streamcreated)
        await controller.reset_conf('__LeaveStreamsUnattached')

    our_stream = [stream for stream in streams if stream.target_address == host][0]

    self.assertTrue(our_stream.circ_id)
    self.assertTrue(circuit_id)

    self.assertEqual(our_stream.circ_id, circuit_id)

  @test.require.controller
  @test.require.online
  @async_test
  async def test_get_circuits(self):
    """
    Fetches circuits via the get_circuits() method.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      new_circ = await controller.new_circuit()
      circuits = await controller.get_circuits()
      self.assertTrue(new_circ in [circ.id for circ in circuits])

  @test.require.controller
  @async_test
  async def test_transition_to_relay(self):
    """
    Transitions Tor to turn into a relay, then back to a client. This helps to
    catch transition issues such as the one cited in :ticket:`tor-14901`.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      try:
        await controller.reset_conf('OrPort', 'DisableNetwork')
        self.assertEqual(None, await controller.get_conf('OrPort'))

        # DisableNetwork ensures no port is actually opened
        await controller.set_options({'OrPort': '9090', 'DisableNetwork': '1'})

        # TODO once tor 0.2.7.x exists, test that we can generate a descriptor on demand.

        self.assertEqual('9090', await controller.get_conf('OrPort'))
        await controller.reset_conf('OrPort', 'DisableNetwork')
        self.assertEqual(None, await controller.get_conf('OrPort'))
      finally:
        await controller.set_conf('OrPort', str(test.runner.ORPORT))

  @test.require.controller
  @async_test
  async def test_hidden_service_auth(self):
    """
    Exercises adding, viewing and removing authentication credentials for a v3
    service.
    """

    async with await test.runner.get_runner().get_tor_controller() as controller:
      # register authentication credentials

      await controller.add_hidden_service_auth(SERVICE_ID, PRIVATE_KEY, client_name = 'StemInteg')

      credential = await controller.list_hidden_service_auth(SERVICE_ID)

      self.assertEqual(SERVICE_ID, credential.service_id)
      self.assertEqual(PRIVATE_KEY, credential.private_key)
      self.assertEqual('x25519', credential.key_type)
      self.assertEqual([], credential.flags)

      # TODO: We should assert our client_name's value...
      #
      #   self.assertEqual('StemInteg', credential.client_name)
      #
      # ... but that's broken within tor...
      #
      #   https://gitlab.torproject.org/tpo/core/tor/-/issues/40089

      # deregister authentication credentials

      await controller.remove_hidden_service_auth(SERVICE_ID)
      self.assertEqual({}, await controller.list_hidden_service_auth())

      # TODO: We should add a persistance test (calling with 'write = True')
      # but that doesn't look to be working...
      #
      #   https://gitlab.torproject.org/tpo/core/tor/-/issues/40090

  @test.require.controller
  @async_test
  async def test_hidden_service_auth_invalid(self):
    """
    Exercises hidden service authentication with invalid data.
    """

    # TODO: This checks for both 'addr' and 'address' because tor runs our
    # integration tests both before and after...
    #
    #   https://gitlab.torproject.org/tpo/core/tor/-/issues/40005
    #
    # After a while we should be able to drop this.

    async with await test.runner.get_runner().get_tor_controller() as controller:
      invalid_service_id = 'xxxxxxxxyvhz3ofkv7gwf5hpzqvhonpr3gbax2cc7dee3xcnt7dmtlx2gu7vyvid'
      exc_msg = "^%%s response didn't have an OK status: Invalid v3 (addr|address) \"%s\"$" % invalid_service_id

      with self.assertRaisesRegexp(stem.ProtocolError, exc_msg % 'ONION_CLIENT_AUTH_ADD'):
        await controller.add_hidden_service_auth(invalid_service_id, PRIVATE_KEY)

      with self.assertRaisesRegexp(stem.ProtocolError, exc_msg % 'ONION_CLIENT_AUTH_REMOVE'):
        await controller.remove_hidden_service_auth(invalid_service_id)

      with self.assertRaisesRegexp(stem.ProtocolError, exc_msg % 'ONION_CLIENT_AUTH_VIEW'):
        await controller.list_hidden_service_auth(invalid_service_id)

      invalid_key = 'XXXXXXXXXFCV0c0ELDKKDpSFgVIB8Yow8Evj5iD+GoiTtK878NkQ='

      # register with an invalid key

      with self.assertRaisesWith(stem.ProtocolError, "ONION_CLIENT_AUTH_ADD response didn't have an OK status: Failed to decode x25519 private key"):
        await controller.add_hidden_service_auth(SERVICE_ID, invalid_key)

  async def _get_router_status_entry(self, controller):
    """
    Provides a router status entry for a relay with a nickname other than
    'Unnamed'. This fails the test if unable to find one.
    """

    global TEST_ROUTER_STATUS_ENTRY

    if TEST_ROUTER_STATUS_ENTRY is None:
      async for desc in controller.get_network_statuses():
        if desc.nickname != 'Unnamed' and Flag.NAMED in desc.flags:
          TEST_ROUTER_STATUS_ENTRY = desc
          break

      if TEST_ROUTER_STATUS_ENTRY is None:
        # this is only likely to occure if we can't get descriptors
        self.skipTest('(no named relays)')

    return TEST_ROUTER_STATUS_ENTRY
