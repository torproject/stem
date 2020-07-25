"""
Unit tests for the stem.util.asyncio module.
"""

import asyncio
import io
import unittest

from unittest.mock import patch, Mock

from stem.util.asyncio import Synchronous
from stem.util.test_tools import coro_func_returning_value

EXAMPLE_OUTPUT = """\
hello from a synchronous context
hello from an asynchronous context
"""


class Demo(Synchronous):
  def __init__(self):
    super(Demo, self).__init__()

    self.called_enter = False
    self.called_exit = False

  def __ainit__(self):
    self.ainit_loop = asyncio.get_running_loop()

  async def async_method(self):
    return 'async call'

  def sync_method(self):
    return 'sync call'

  async def __aiter__(self):
    for i in range(3):
      yield i

  async def __aenter__(self):
    self.called_enter = True
    return self

  async def __aexit__(self, exit_type, value, traceback):
    self.called_exit = True
    return


class TestSynchronous(unittest.TestCase):
  @patch('sys.stdout', new_callable = io.StringIO)
  def test_example(self, stdout_mock):
    """
    Run the example from our pydoc.
    """

    class Example(Synchronous):
      async def hello(self):
        return 'hello'

    def sync_demo():
      instance = Example()
      print('%s from a synchronous context' % instance.hello())
      instance.stop()

    async def async_demo():
      instance = Example()
      print('%s from an asynchronous context' % await instance.hello())
      instance.stop()

    sync_demo()
    asyncio.run(async_demo())

    self.assertEqual(EXAMPLE_OUTPUT, stdout_mock.getvalue())

  def test_is_asyncio_context(self):
    """
    Check that we can differentiate a synchronous from an async context.
    """

    def sync_test():
      self.assertFalse(Synchronous.is_asyncio_context())

    async def async_test():
      self.assertTrue(Synchronous.is_asyncio_context())

    sync_test()
    asyncio.run(async_test())

  def test_ainit(self):
    """
    Check that construction runs __ainit__ with a loop when present.
    """

    def sync_test():
      instance = Demo()
      self.assertTrue(isinstance(instance.ainit_loop, asyncio.AbstractEventLoop))
      instance.stop()

    async def async_test():
      instance = Demo()
      self.assertTrue(isinstance(instance.ainit_loop, asyncio.AbstractEventLoop))
      instance.stop()

    sync_test()
    asyncio.run(async_test())

  def test_stop(self):
    """
    Stop and resume our instances.
    """

    def sync_test():
      instance = Demo()
      self.assertEqual('async call', instance.async_method())
      instance.stop()

      # synchronous methods won't resume us

      self.assertEqual('sync call', instance.sync_method())
      self.assertTrue(instance._loop is None)

      # ... but async methods will

      self.assertEqual('async call', instance.async_method())
      self.assertTrue(isinstance(instance._loop, asyncio.AbstractEventLoop))

      instance.stop()

    async def async_test():
      instance = Demo()
      self.assertEqual('async call', await instance.async_method())
      instance.stop()

      # stop has no affect on async users

      self.assertEqual('async call', await instance.async_method())

    sync_test()
    asyncio.run(async_test())

  def test_stop_from_async(self):
    """
    Ensure we can restart and stop our instance from within an async method
    without deadlock.
    """

    class AsyncStop(Synchronous):
      async def restart(self):
        self.stop()
        self.start()

      async def call_stop(self):
        self.stop()

    instance = AsyncStop()
    instance.restart()
    instance.call_stop()
    self.assertTrue(instance._loop is None)

  def test_iteration(self):
    """
    Check that we can iterate in both contexts.
    """

    def sync_test():
      instance = Demo()
      result = []

      for val in instance:
        result.append(val)

      self.assertEqual([0, 1, 2], result)
      instance.stop()

    async def async_test():
      instance = Demo()
      result = []

      async for val in instance:
        result.append(val)

      self.assertEqual([0, 1, 2], result)
      instance.stop()

    sync_test()
    asyncio.run(async_test())

  def test_context_management(self):
    """
    Exercise context management via 'with' statements.
    """

    def sync_test():
      instance = Demo()

      self.assertFalse(instance.called_enter)
      self.assertFalse(instance.called_exit)

      with instance:
        self.assertTrue(instance.called_enter)
        self.assertFalse(instance.called_exit)

      self.assertTrue(instance.called_enter)
      self.assertTrue(instance.called_exit)

      instance.stop()

    async def async_test():
      instance = Demo()

      self.assertFalse(instance.called_enter)
      self.assertFalse(instance.called_exit)

      async with instance:
        self.assertTrue(instance.called_enter)
        self.assertFalse(instance.called_exit)

      self.assertTrue(instance.called_enter)
      self.assertTrue(instance.called_exit)

      instance.stop()

    sync_test()
    asyncio.run(async_test())

  def test_mockability(self):
    """
    Check that method mocks are respected for both previously constructed
    instances and those made after the mock.
    """

    pre_constructed = Demo()

    with patch('test.unit.util.asyncio.Demo.async_method', Mock(side_effect = coro_func_returning_value('mocked call'))):
      post_constructed = Demo()

      self.assertEqual('mocked call', pre_constructed.async_method())
      self.assertEqual('mocked call', post_constructed.async_method())

    self.assertEqual('async call', pre_constructed.async_method())
    self.assertEqual('async call', post_constructed.async_method())

    # synchronous methods are unaffected

    with patch('test.unit.util.asyncio.Demo.sync_method', Mock(return_value = 'mocked call')):
      self.assertEqual('mocked call', pre_constructed.sync_method())

    self.assertEqual('sync call', pre_constructed.sync_method())

    pre_constructed.stop()
    post_constructed.stop()
