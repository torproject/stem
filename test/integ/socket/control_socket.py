"""
Integration tests for the stem.socket.ControlSocket subclasses. When ran these
test basic functionality for a ControlPort *or* ControlSocketFile, depending on
which can connect to our tor instance.

These tests share a similar domain with those for the ControlMessage, but where
those focus on parsing and correctness of the content these are more concerned
with the behavior of the socket itself.
"""

import time
import unittest

import stem.connection
import stem.control
import stem.socket
import test
import test.require
import test.runner


class TestControlSocket(unittest.TestCase):
  @test.require.controller
  def test_connection_time(self):
    """
    Checks that our connection_time method tracks when our state's changed.
    """

    test_start = time.time()
    runner = test.runner.get_runner()

    with runner.get_tor_socket() as control_socket:
      connection_time = control_socket.connection_time()

      # connection time should be between our tests start and now

      self.assertTrue(test_start <= connection_time <= time.time())

      # connection time should be absolute (shouldn't change as time goes on)

      time.sleep(0.001)
      self.assertEqual(connection_time, control_socket.connection_time())

      # should change to the disconnection time if we detactch

      control_socket.close()
      disconnection_time = control_socket.connection_time()
      self.assertTrue(connection_time < disconnection_time <= time.time())

      # then change again if we reconnect

      time.sleep(0.001)
      control_socket.connect()
      reconnection_time = control_socket.connection_time()
      self.assertTrue(disconnection_time < reconnection_time <= time.time())

  @test.require.controller
  def test_send_buffered(self):
    """
    Sends multiple requests before receiving back any of the replies.
    """

    runner = test.runner.get_runner()

    with runner.get_tor_socket() as control_socket:
      for _ in range(100):
        control_socket.send('GETINFO version')

      for _ in range(100):
        response = control_socket.recv()
        self.assertTrue(str(response).startswith('version=%s' % test.tor_version()))
        self.assertTrue(str(response).endswith('\nOK'))

  @test.require.controller
  def test_send_closed(self):
    """
    Sends a message after we've closed the connection.
    """

    with test.runner.get_runner().get_tor_socket() as control_socket:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      self.assertFalse(control_socket.is_alive())

      self.assertRaises(stem.SocketClosed, control_socket.send, 'blarg')

  @test.require.controller
  def test_send_disconnected(self):
    """
    Sends a message to a socket that has been disconnected by the other end.

    Our behavior upon disconnection slightly differs based on if we're a port
    or socket file based connection. With a control port we won't notice the
    disconnect (is_alive() will return True) until we've made a failed recv()
    call. With a file socket, however, we'll also fail when calling send().
    """

    with test.runner.get_runner().get_tor_socket() as control_socket:
      control_socket.send('QUIT')
      self.assertEqual('closing connection', str(control_socket.recv()))
      self.assertTrue(control_socket.is_alive())

      # If we send another message to a port based socket then it will seem to
      # succeed. However, a file based socket should report a failure.

      if isinstance(control_socket, stem.socket.ControlPort):
        control_socket.send('blarg')
        self.assertTrue(control_socket.is_alive())
      else:
        self.assertRaises(stem.SocketClosed, control_socket.send, 'blarg')
        self.assertFalse(control_socket.is_alive())

  @test.require.controller
  def test_recv_closed(self):
    """
    Receives a message after we've closed the connection.
    """

    with test.runner.get_runner().get_tor_socket() as control_socket:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      self.assertFalse(control_socket.is_alive())

      self.assertRaises(stem.SocketClosed, control_socket.recv)

  @test.require.controller
  def test_recv_disconnected(self):
    """
    Receives a message from a socket that has been disconnected by the other
    end.
    """

    with test.runner.get_runner().get_tor_socket() as control_socket:
      control_socket.send('QUIT')
      self.assertEqual('closing connection', str(control_socket.recv()))

      # Neither a port or file based socket will know that tor has hung up on
      # the connection at this point. We should know after calling recv(),
      # however.

      self.assertTrue(control_socket.is_alive())
      self.assertRaises(stem.SocketClosed, control_socket.recv)
      self.assertFalse(control_socket.is_alive())

  @test.require.controller
  def test_connect_repeatedly(self):
    """
    Checks that we can reconnect, use, and disconnect a socket repeatedly.
    """

    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      for _ in range(10):
        # this will raise if the PROTOCOLINFO query fails
        stem.connection.get_protocolinfo(control_socket)

        control_socket.close()
        self.assertRaises(stem.SocketClosed, control_socket.send, 'PROTOCOLINFO 1')
        control_socket.connect()
