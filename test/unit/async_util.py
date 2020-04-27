import asyncio
import functools


def async_test(func):
  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    loop = asyncio.new_event_loop()
    try:
      result = loop.run_until_complete(func(*args, **kwargs))
    finally:
      loop.close()
    return result
  return wrapper


def coro_func_returning_value(return_value):
  async def coroutine_func(*args, **kwargs):
    return return_value
  return coroutine_func


def coro_func_raising_exc(exc):
  async def coroutine_func(*args, **kwargs):
    raise exc
  return coroutine_func
