# Copyright 2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Utilities for working with asyncio.
"""

import asyncio
import functools
import inspect
import threading
import unittest.mock

from types import TracebackType
from typing import Any, AsyncIterator, Iterator, Optional, Type


class Synchronous(object):
  """
  Mixin that lets a class run within both synchronous and asynchronous
  contexts.

  ::

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

  Our async methods always run within a loop. For asyncio users this class has
  no affect, but otherwise we transparently create an async context to run
  within.

  Class initialization and any non-async methods should assume they're running
  within an synchronous context. If our class supplies an **__ainit__()**
  method it is invoked within our loop during initialization...

  ::

    class Example(Synchronous):
      def __init__(self):
        super(Example, self).__init__()

        # Synchronous part of our initialization. Avoid anything
        # that must run within an asyncio loop.

      def __ainit__(self):
        # Asychronous part of our initialization. You can call
        # asyncio.get_running_loop(), and construct objects that
        # require it (like asyncio.Queue and asyncio.Lock).

  Users are responsible for calling :func:`~stem.util.Synchronous.stop` when
  finished to clean up underlying resources.
  """

  def __init__(self) -> None:
    self._loop = None  # type: Optional[asyncio.AbstractEventLoop]
    self._loop_thread = None  # type: Optional[threading.Thread]
    self._loop_lock = threading.RLock()

    # this class is a no-op when created within an asyncio context

    self._no_op = Synchronous.is_asyncio_context()

    if self._no_op:
      # TODO: replace with get_running_loop() when we remove python 3.6 support

      self._loop = asyncio.get_event_loop()
      self.__ainit__()  # this is already an asyncio context
    else:
      # Run coroutines through our loop. This calls methods by name rather than
      # reference so runtime replacements (like mocks) work.

      for name, func in inspect.getmembers(self):
        if name in ('__aiter__', '__aenter__', '__aexit__'):
          pass  # async object methods with synchronous counterparts
        elif isinstance(func, unittest.mock.Mock) and (inspect.iscoroutinefunction(func.side_effect) or inspect.isasyncgenfunction(func.side_effect)):
          setattr(self, name, functools.partial(self._run_async_method, name))
        elif inspect.ismethod(func) and (inspect.iscoroutinefunction(func) or inspect.isasyncgenfunction(func)):
          setattr(self, name, functools.partial(self._run_async_method, name))

      Synchronous.start(self)

      async def convert_ainit():
        return self.__ainit__()
      asyncio.run_coroutine_threadsafe(convert_ainit(), self._loop).result()

  def __ainit__(self):
    """
    Implicitly called during construction. This method is assured to have an
    asyncio loop during its execution.
    """

    # This method should be async (so 'await' works), but apparently that
    # is not possible.
    #
    # When our object is constructed our __init__() can be called from a
    # synchronous or asynchronous context. If synchronous, it's trivial to
    # run an asynchronous variant of this method because we fully control
    # the execution of our loop...
    #
    #   asyncio.run_coroutine_threadsafe(self.__ainit__(), self._loop).result()
    #
    # However, when constructed from an asynchronous context the above will
    # likely hang because our loop is already processing a task (namely,
    # whatever is constructing us). While we can schedule a follow-up task, we
    # cannot invoke it during our construction.
    #
    # Finally, when this method is simple we could directly invoke it...
    #
    #   class Synchronous(object):
    #     def __init__(self):
    #       if Synchronous.is_asyncio_context():
    #         try:
    #           self.__ainit__().send(None)
    #         except StopIteration:
    #           pass
    #       else:
    #         asyncio.run_coroutine_threadsafe(self.__ainit__(), self._loop).result()
    #
    #     async def __ainit__(self):
    #       # asynchronous construction
    #
    # However, this breaks if any 'await' suspends our execution. For more
    # information see...
    #
    #   https://stackoverflow.com/questions/52783605/how-to-run-a-coroutine-outside-of-an-event-loop/52829325#52829325

    pass

  def start(self) -> None:
    """
    Initiate resources to make this object callable from synchronous contexts.
    """

    with self._loop_lock:
      if not self._no_op and self._loop is None:
        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(
          name = '%s asyncio' % type(self).__name__,
          target = self._loop.run_forever,
          daemon = True,
        )

        self._loop_thread.start()

  def stop(self) -> None:
    """
    Terminate resources that permits this from being callable from synchronous
    contexts. Calling either :func:`~stem.util.Synchronous.start` or any async
    method will resume us.
    """

    with self._loop_lock:
      if not self._no_op and self._loop is not None:
        self._loop.call_soon_threadsafe(self._loop.stop)

        if threading.current_thread() != self._loop_thread:
          self._loop_thread.join()

        self._loop = None
        self._loop_thread = None

  @staticmethod
  def is_asyncio_context() -> bool:
    """
    Check if running within a synchronous or asynchronous context.

    :returns: **True** if within an asyncio conext, **False** otherwise
    """

    try:
      asyncio.get_running_loop()
      return True
    except RuntimeError:
      return False
    except AttributeError:
      # TODO: drop when we remove python 3.6 support

      try:
        return asyncio._get_running_loop() is not None
      except AttributeError:
        return False  # python 3.5.3 or below

  def _run_async_method(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
    """
    Run this async method from either a synchronous or asynchronous context.

    :param method_name: name of the method to invoke
    :param args: positional arguments
    :param kwargs: keyword arguments

    :returns: method's return value

    :raises: **AttributeError** if this method doesn't exist
    """

    func = getattr(type(self), method_name, None)

    if not func:
      raise AttributeError("'%s' does not have a %s method" % (type(self).__name__, method_name))
    elif self._no_op or Synchronous.is_asyncio_context():
      return func(self, *args, **kwargs)

    with self._loop_lock:
      if self._loop is None:
        Synchronous.start(self)

      if inspect.isasyncgenfunction(func):
        async def convert_generator(generator: AsyncIterator) -> Iterator:
          return iter([d async for d in generator])

        future = asyncio.run_coroutine_threadsafe(convert_generator(func(self, *args, **kwargs)), self._loop)
      else:
        future = asyncio.run_coroutine_threadsafe(func(self, *args, **kwargs), self._loop)

    return future.result()

  def __iter__(self) -> Iterator:
    return self._run_async_method('__aiter__')

  def __enter__(self):
    return self._run_async_method('__aenter__')

  def __exit__(self, exit_type: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]):
    return self._run_async_method('__aexit__', exit_type, value, traceback)
