"""
Integration tests for establishing a connection with tor's ORPort.
"""

import time
import unittest

import stem
import test.runner

from stem.client import Relay


class TestConnection(unittest.TestCase):
  def test_invalid_arguments(self):
    """
    Provide invalid arguments to Relay.connect().
    """

    self.assertRaisesWith(ValueError, "'nope' isn't an IPv4 or IPv6 address", Relay.connect, 'nope', 80)
    self.assertRaisesWith(ValueError, "'-54' isn't a valid port", Relay.connect, '127.0.0.1', -54)
    self.assertRaisesWith(ValueError, "Connection can't be established without a link protocol.", Relay.connect, '127.0.0.1', 54, [])

  def test_not_orport(self):
    """
    Attempt to connect to an ORPort that doesn't exist.
    """

    self.assertRaisesWith(stem.SocketError, "Failed to connect to 127.0.0.1:1587. Maybe it isn't an ORPort?", Relay.connect, '127.0.0.1', 1587)

    # connect to our ControlPort like it's an ORPort

    if test.runner.Torrc.PORT in test.runner.get_runner().get_options():
      self.assertRaisesWith(stem.SocketError, "Failed to SSL authenticate to 127.0.0.1:1111. Maybe it isn't an ORPort?", Relay.connect, '127.0.0.1', test.runner.CONTROL_PORT)

  def test_no_common_link_protocol(self):
    """
    Connection without a commonly accepted link protocol version.
    """

    for link_protocol in (1, 2, 6, 20):
      self.assertRaisesWith(stem.SocketError, 'Unable to establish a common link protocol with 127.0.0.1:1113', Relay.connect, '127.0.0.1', test.runner.ORPORT, [link_protocol])

  def test_connection_time(self):
    """
    Checks duration we've been connected.
    """

    before = time.time()

    with Relay.connect('127.0.0.1', test.runner.ORPORT) as conn:
      connection_time = conn.connection_time()
      self.assertTrue(time.time() >= connection_time >= before)
      time.sleep(0.02)
      self.assertTrue(conn.is_alive())

    self.assertFalse(conn.is_alive())
    self.assertTrue(conn.connection_time() >= connection_time + 0.02)

  def test_established(self):
    """
    Successfully establish ORPort connection.
    """

    conn = Relay.connect('127.0.0.1', test.runner.ORPORT)
    self.assertTrue(int(conn.link_protocol) in (4, 5))
