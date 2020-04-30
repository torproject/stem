"""
Integration tests for the stem.control.BaseController class.
"""

import asyncio
import os
import hashlib
import random
import re
import time
import unittest

import stem.control
import stem.socket
import stem.util.system
import test.require
import test.runner
from test.async_util import async_test


class StateObserver(object):
  """
  Simple container for listening to ControlSocket state changes and
  rembembering them for the test.
  """

  controller = None
  state = None
  timestamp = None

  def reset(self):
    self.controller = None
    self.state = None
    self.timestamp = None

  def listener(self, controller, state, timestamp):
    self.controller = controller
    self.state = state
    self.timestamp = timestamp


class TestBaseController(unittest.TestCase):
  @test.require.controller
  @async_test
  async def test_connect_repeatedly(self):
    """
    Connects and closes the socket repeatedly. This is a simple attempt to
    trigger concurrency issues.
    """

    if stem.util.system.is_mac():
      self.skipTest('(ticket #6235)')

    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = stem.control.BaseController(control_socket)

      for _ in range(50):
        await controller.connect()
        await controller.close()

  @test.require.controller
  @async_test
  async def test_msg(self):
    """
    Tests a basic query with the msg() method.
    """

    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = stem.control.BaseController(control_socket)
      await test.runner.exercise_controller(self, controller)

  @test.require.controller
  @async_test
  async def test_msg_invalid(self):
    """
    Tests the msg() method against an invalid controller command.
    """

    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = stem.control.BaseController(control_socket)
      response = await controller.msg('invalid')
      self.assertEqual('Unrecognized command "invalid"', str(response))

  @test.require.controller
  @async_test
  async def test_msg_invalid_getinfo(self):
    """
    Tests the msg() method against a non-existant GETINFO option.
    """

    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = stem.control.BaseController(control_socket)
      response = await controller.msg('GETINFO blarg')
      self.assertEqual('Unrecognized key "blarg"', str(response))

  @test.require.controller
  @async_test
  async def test_msg_repeatedly(self):
    """
    Connects, sends a burst of messages, and closes the socket repeatedly. This
    is a simple attempt to trigger concurrency issues.
    """

    if stem.util.system.is_mac():
      self.skipTest('(ticket #6235)')

    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = stem.control.BaseController(control_socket)

      async def connect_and_close():
        await controller.connect()
        await controller.close()

      async def run_getinfo():
        for _ in range(50):
          try:
            await controller.msg('GETINFO version')
            await controller.msg('GETINFO blarg')
            await controller.msg('blarg')
          except stem.ControllerError:
            pass

      coroutines = [connect_and_close()] * 50
      coroutines.extend(run_getinfo() for _ in range(5))
      random.shuffle(coroutines)

      await asyncio.gather(*coroutines)

  @test.require.controller
  @async_test
  async def test_asynchronous_event_handling(self):
    """
    Check that we can both receive asynchronous events while hammering our
    socket with queries, and checks that when a controller is closed the
    listeners will still receive all of the enqueued events.
    """

    class ControlledListener(stem.control.BaseController):
      """
      Controller that blocks event handling until told to do so.
      """

      def __init__(self, control_socket):
        stem.control.BaseController.__init__(self, control_socket)
        self.received_events = []
        self.receive_notice = asyncio.Event()

      async def _handle_event(self, event_message):
        await self.receive_notice.wait()
        self.received_events.append(event_message)

    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = ControlledListener(control_socket)
      await controller.msg('SETEVENTS CONF_CHANGED')

      for i in range(10):
        fingerprint = hashlib.sha1(os.urandom(20)).hexdigest().upper()
        await controller.msg('SETCONF NodeFamily=%s' % fingerprint)
        await test.runner.exercise_controller(self, controller)

      await controller.msg('SETEVENTS')
      await controller.msg('RESETCONF NodeFamily')

      await controller.close()
      controller.receive_notice.set()
      await asyncio.sleep(0)

      self.assertTrue(len(controller.received_events) >= 2)

      for conf_changed_event in controller.received_events:
        self.assertTrue(re.match('CONF_CHANGED\nNodeFamily=*', str(conf_changed_event)))
        self.assertTrue(conf_changed_event.raw_content().startswith('650-CONF_CHANGED\r\n650-NodeFamily='))
        self.assertEqual(('650', '-'), conf_changed_event.content()[0][:2])

  @test.require.controller
  @async_test
  async def test_get_latest_heartbeat(self):
    """
    Basic check for get_latest_heartbeat().
    """

    # makes a getinfo query, then checks that the heartbeat is close to now
    async with await test.runner.get_runner().get_tor_socket() as control_socket:
      controller = stem.control.BaseController(control_socket)
      await controller.msg('GETINFO version')
      self.assertTrue((time.time() - controller.get_latest_heartbeat()) < 5)

  @test.require.controller
  @async_test
  async def test_status_notifications(self):
    """
    Checks basic functionality of the add_status_listener() and
    remove_status_listener() methods.
    """

    state_observer = StateObserver()

    async with await test.runner.get_runner().get_tor_socket(False) as control_socket:
      controller = stem.control.BaseController(control_socket)
      controller.add_status_listener(state_observer.listener, False)

      await controller.close()
      self.assertEqual(controller, state_observer.controller)
      self.assertEqual(stem.control.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp <= time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()

      await controller.connect()
      self.assertEqual(controller, state_observer.controller)
      self.assertEqual(stem.control.State.INIT, state_observer.state)
      self.assertTrue(state_observer.timestamp <= time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()

      # cause the socket to shut down without calling close()
      await controller.msg('Blarg!')
      with self.assertRaises(stem.SocketClosed):
        await controller.msg('blarg')
      self.assertEqual(controller, state_observer.controller)
      self.assertEqual(stem.control.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp <= time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()

      # remove listener and make sure we don't get further notices
      controller.remove_status_listener(state_observer.listener)
      await controller.connect()
      self.assertEqual(None, state_observer.controller)
      self.assertEqual(None, state_observer.state)
      self.assertEqual(None, state_observer.timestamp)
      state_observer.reset()

      # add with spawn as true, we need a little delay on this since we then
      # get the notice asynchronously

      controller.add_status_listener(state_observer.listener, True)
      await controller.close()
      await asyncio.sleep(0.001)  # not much work going on so this doesn't need to be much
      self.assertEqual(controller, state_observer.controller)
      self.assertEqual(stem.control.State.CLOSED, state_observer.state)
      self.assertTrue(state_observer.timestamp <= time.time())
      self.assertTrue(state_observer.timestamp > time.time() - 1.0)
      state_observer.reset()
