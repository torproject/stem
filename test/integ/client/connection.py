"""
Integration tests for establishing a connection with tor's ORPort.
"""

import time
import unittest

import stem
import test.runner

from stem.client import Relay
from stem.util.test_tools import async_test


class TestConnection(unittest.TestCase):
  @async_test
  async def test_invalid_arguments(self):
    """
    Provide invalid arguments to Relay.connect().
    """

    with self.assertRaisesWith(ValueError, "'nope' isn't an IPv4 or IPv6 address"):
      await Relay.connect('nope', 80)
    with self.assertRaisesWith(ValueError, "'-54' isn't a valid port"):
      await Relay.connect('127.0.0.1', -54)
    with self.assertRaisesWith(ValueError, "Connection can't be established without a link protocol."):
      await Relay.connect('127.0.0.1', 54, [])

  @async_test
  async def test_not_orport(self):
    """
    Attempt to connect to an ORPort that doesn't exist.
    """

    with self.assertRaisesWith(stem.SocketError, "Failed to connect to 127.0.0.1:1587. Maybe it isn't an ORPort?"):
      await Relay.connect('127.0.0.1', 1587)

    # connect to our ControlPort like it's an ORPort

    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      with self.assertRaisesWith(stem.SocketError, "Failed to SSL authenticate to 127.0.0.1:1111. Maybe it isn't an ORPort?"):
        await Relay.connect('127.0.0.1', test.runner.CONTROL_PORT)

  @async_test
  async def test_no_common_link_protocol(self):
    """
    Connection without a commonly accepted link protocol version.
    """

    for link_protocol in (1, 2, 6, 20):
      with self.assertRaisesWith(stem.SocketError, 'Unable to establish a common link protocol with 127.0.0.1:1113'):
        await Relay.connect('127.0.0.1', test.runner.ORPORT, [link_protocol])

  @async_test
  async def test_connection_time(self):
    """
    Checks duration we've been connected.
    """

    before = time.time()

    async with await Relay.connect('127.0.0.1', test.runner.ORPORT) as conn:
      connection_time = conn.connection_time()
      self.assertTrue(time.time() >= connection_time >= before)
      time.sleep(0.02)
      self.assertTrue(conn.is_alive())

    self.assertFalse(conn.is_alive())
    self.assertTrue(conn.connection_time() >= connection_time + 0.02)

  @async_test
  async def test_established(self):
    """
    Successfully establish ORPort connection.
    """

    conn = await Relay.connect('127.0.0.1', test.runner.ORPORT)
    self.assertTrue(int(conn.link_protocol) in (4, 5))
