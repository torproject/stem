# Copyright 2011-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Utility functions used by the stem library.
"""

import asyncio
import datetime
import functools
import inspect
import threading
from concurrent.futures import Future

from typing import Any, AsyncIterator, Callable, Iterator, Optional, Type, Union

__all__ = [
  'conf',
  'connection',
  'enum',
  'log',
  'lru_cache',
  'ordereddict',
  'proc',
  'str_tools',
  'system',
  'term',
  'test_tools',
  'tor_tools',

  'datetime_to_unix',
]

# Beginning with Stem 1.7 we take attribute types into account when hashing
# and checking equality. That is to say, if two Stem classes' attributes are
# the same but use different types we no longer consider them to be equal.
# For example...
#
#   s1 = Schedule(classes = ['Math', 'Art', 'PE'])
#   s2 = Schedule(classes = ('Math', 'Art', 'PE'))
#
# Prior to Stem 1.7 s1 and s2 would be equal, but afterward unless Stem's
# construcotr normalizes the types they won't.
#
# This change in behavior is the right thing to do but carries some risk, so
# we provide the following constant to revert to legacy behavior. If you find
# yourself using it them please let me know (https://www.atagar.com/contact/)
# since this flag will go away in the future.

HASH_TYPES = True


def _hash_value(val: Any) -> int:
  if not HASH_TYPES:
    my_hash = 0
  else:
    # Hashing common builtins (ints, bools, etc) provide consistant values but
    # many others vary their value on interpreter invokation.

    my_hash = hash(str(type(val)))

  if isinstance(val, (tuple, list)):
    for v in val:
      my_hash = (my_hash * 1024) + hash(v)
  elif isinstance(val, dict):
    for k in sorted(val.keys()):
      my_hash = (my_hash * 2048) + (hash(k) * 1024) + hash(val[k])
  else:
    my_hash += hash(val)

  return my_hash


def datetime_to_unix(timestamp: 'datetime.datetime') -> float:
  """
  Converts a utc datetime object to a unix timestamp.

  .. versionadded:: 1.5.0

  :param timestamp: timestamp to be converted

  :returns: **float** for the unix timestamp of the given datetime object
  """

  return (timestamp - datetime.datetime(1970, 1, 1)).total_seconds()


def _pubkey_bytes(key: Union['cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey', 'cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey', 'cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey', 'cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey']) -> bytes:  # type: ignore
  """
  Normalizes X25509 and ED25519 keys into their public key bytes.
  """

  if isinstance(key, bytes):
    return key
  elif isinstance(key, str):
    return key.encode('utf-8')

  try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
  except ImportError:
    raise ImportError('Key normalization requires cryptography 2.6 or later')

  if isinstance(key, (X25519PrivateKey, Ed25519PrivateKey)):
    return key.public_key().public_bytes(
      encoding = serialization.Encoding.Raw,
      format = serialization.PublicFormat.Raw,
    )
  elif isinstance(key, (X25519PublicKey, Ed25519PublicKey)):
    return key.public_bytes(
      encoding = serialization.Encoding.Raw,
      format = serialization.PublicFormat.Raw,
    )
  else:
    raise ValueError('Key must be a string or cryptographic public/private key (was %s)' % type(key).__name__)


def _hash_attr(obj: Any, *attributes: str, **kwargs: Any) -> int:
  """
  Provide a hash value for the given set of attributes.

  :param obj: object to be hashed
  :param attributes: attribute names to take into account
  :param cache: persists hash in a '_cached_hash' object attribute
  :param parent: include parent's hash value

  :returns: **int** object hash
  """

  is_cached = kwargs.get('cache', False)
  parent_class = kwargs.get('parent', None)
  cached_hash = getattr(obj, '_cached_hash', None)

  if is_cached and cached_hash is not None:
    return cached_hash

  my_hash = parent_class.__hash__(obj) if parent_class else 0
  my_hash = my_hash * 1024 + hash(str(type(obj)))

  for attr in attributes:
    val = getattr(obj, attr)
    my_hash = my_hash * 1024 + _hash_value(val)

  if is_cached:
    setattr(obj, '_cached_hash', my_hash)

  return my_hash


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
    self._loop_thread = None  # type: Optional[threading.Thread]
    self._loop_thread_lock = threading.RLock()

    if Synchronous.is_asyncio_context():
      self._loop = asyncio.get_running_loop()

      self.__ainit__()
    else:
      self._loop = asyncio.new_event_loop()

      Synchronous.start(self)

      # call any coroutines through this loop

      def call_async(func: Callable, *args: Any, **kwargs: Any) -> Any:
        if Synchronous.is_asyncio_context():
          return func(*args, **kwargs)

        with self._loop_thread_lock:
          if not self._loop_thread.is_alive():
            raise RuntimeError('%s has been stopped' % type(self).__name__)

          return asyncio.run_coroutine_threadsafe(func(*args, **kwargs), self._loop).result()

      for method_name, func in inspect.getmembers(self, predicate = inspect.ismethod):
        if inspect.iscoroutinefunction(func):
          setattr(self, method_name, functools.partial(call_async, func))

      asyncio.run_coroutine_threadsafe(asyncio.coroutine(self.__ainit__)(), self._loop).result()

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
    # whatever is constructing us). While we can schedule tasks, we cannot
    # invoke it during our construction.
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

    with self._loop_thread_lock:
      self._loop_thread = threading.Thread(
        name = '%s asyncio' % type(self).__name__,
        target = self._loop.run_forever,
        daemon = True,
      )

      self._loop_thread.start()

  def stop(self) -> None:
    """
    Terminate resources that permits this from being callable from synchronous
    contexts. Once called any further synchronous invocations will fail with a
    **RuntimeError**.
    """

    with self._loop_thread_lock:
      if self._loop_thread and self._loop_thread.is_alive():
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._loop_thread.join()

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

  def __iter__(self) -> Iterator:
    async def convert_generator(generator: AsyncIterator) -> Iterator:
      return iter([d async for d in generator])

    iter_func = getattr(self, '__aiter__', None)

    if iter_func:
      return asyncio.run_coroutine_threadsafe(convert_generator(iter_func()), self._loop).result()
    else:
      raise TypeError("'%s' object is not iterable" % type(self).__name__)


class AsyncClassWrapper:
  _loop: asyncio.AbstractEventLoop
  _loop_thread: threading.Thread
  _wrapped_instance: type

  def _init_async_class(self, async_class: Type, *args: Any, **kwargs: Any) -> Any:
    # The asynchronous class should be initialized in the thread where
    # its methods will be executed.
    if self._loop_thread != threading.current_thread():
      async def init():
        return async_class(*args, **kwargs)

      return asyncio.run_coroutine_threadsafe(init(), self._loop).result()

    return async_class(*args, **kwargs)

  def _call_async_method_soon(self, method_name: str, *args: Any, **kwargs: Any) -> Future:
    return asyncio.run_coroutine_threadsafe(
      getattr(self._wrapped_instance, method_name)(*args, **kwargs),
      self._loop,
    )

  def _execute_async_method(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
    return self._call_async_method_soon(method_name, *args, **kwargs).result()

  def _execute_async_generator_method(self, method_name: str, *args: Any, **kwargs: Any) -> Iterator:
    async def convert_async_generator(generator: AsyncIterator) -> Iterator:
      return iter([d async for d in generator])

    return asyncio.run_coroutine_threadsafe(
      convert_async_generator(
        getattr(self._wrapped_instance, method_name)(*args, **kwargs),
      ),
      self._loop,
    ).result()

  def __del__(self) -> None:
    self._loop.call_soon_threadsafe(self._loop.stop)
    self._loop_thread.join()
