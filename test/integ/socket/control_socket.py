"""
Integration tests for the stem.socket.ControlSocket subclasses. When ran these
test basic functionality for a ControlPort *or* ControlSocketFile, depending on
which can connect to our tor instance.

These tests share a similar domain with those for the ControlMessage, but where
those focus on parsing and correctness of the content these are more concerned
with the behavior of the socket itself.
"""

import unittest

import stem.connection
import stem.control
import stem.socket
import test.runner


class TestControlSocket(unittest.TestCase):
  def test_send_buffered(self):
    """
    Sends multiple requests before receiving back any of the replies.
    """

    if test.runner.require_control(self):
      return

    runner = test.runner.get_runner()
    tor_version = runner.get_tor_version()

    with runner.get_tor_socket() as control_socket:
      for _ in range(100):
        control_socket.send('GETINFO version')

      for _ in range(100):
        response = control_socket.recv()
        self.assertTrue(str(response).startswith('version=%s' % tor_version))
        self.assertTrue(str(response).endswith('\nOK'))

  def test_send_closed(self):
    """
    Sends a message after we've closed the connection.
    """

    if test.runner.require_control(self):
      return

    with test.runner.get_runner().get_tor_socket() as control_socket:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      self.assertFalse(control_socket.is_alive())

      self.assertRaises(stem.SocketClosed, control_socket.send, 'blarg')

  def test_send_disconnected(self):
    """
    Sends a message to a socket that has been disconnected by the other end.

    Our behavior upon disconnection slightly differs based on if we're a port
    or socket file based connection. With a control port we won't notice the
    disconnect (is_alive() will return True) until we've made a failed recv()
    call. With a file socket, however, we'll also fail when calling send().
    """

    if test.runner.require_control(self):
      return

    with test.runner.get_runner().get_tor_socket() as control_socket:
      control_socket.send('QUIT')
      self.assertEquals('closing connection', str(control_socket.recv()))
      self.assertTrue(control_socket.is_alive())

      # If we send another message to a port based socket then it will seem to
      # succeed. However, a file based socket should report a failure.

      if isinstance(control_socket, stem.socket.ControlPort):
        control_socket.send('blarg')
        self.assertTrue(control_socket.is_alive())
      else:
        self.assertRaises(stem.SocketClosed, control_socket.send, 'blarg')
        self.assertFalse(control_socket.is_alive())

  def test_recv_closed(self):
    """
    Receives a message after we've closed the connection.
    """

    if test.runner.require_control(self):
      return

    with test.runner.get_runner().get_tor_socket() as control_socket:
      self.assertTrue(control_socket.is_alive())
      control_socket.close()
      self.assertFalse(control_socket.is_alive())

      self.assertRaises(stem.SocketClosed, control_socket.recv)

  def test_recv_disconnected(self):
    """
    Receives a message from a socket that has been disconnected by the other
    end.
    """

    if test.runner.require_control(self):
      return

    with test.runner.get_runner().get_tor_socket() as control_socket:
      control_socket.send('QUIT')
      self.assertEquals('closing connection', str(control_socket.recv()))

      # Neither a port or file based socket will know that tor has hung up on
      # the connection at this point. We should know after calling recv(),
      # however.

      self.assertTrue(control_socket.is_alive())
      self.assertRaises(stem.SocketClosed, control_socket.recv)
      self.assertFalse(control_socket.is_alive())

  def test_connect_repeatedly(self):
    """
    Checks that we can reconnect, use, and disconnect a socket repeatedly.
    """

    if test.runner.require_control(self):
      return

    with test.runner.get_runner().get_tor_socket(False) as control_socket:
      for _ in range(10):
        # this will raise if the PROTOCOLINFO query fails
        stem.connection.get_protocolinfo(control_socket)

        control_socket.close()
        self.assertRaises(stem.SocketClosed, control_socket.send, 'PROTOCOLINFO 1')
        control_socket.connect()
