# Copyright 2011-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Supports communication with sockets speaking Tor protocols. This
allows us to send messages as basic strings, and receive responses as
:class:`~stem.response.ControlMessage` instances.

**This module only consists of low level components, and is not intended for
users.** See our `tutorials <../tutorials.html>`_ and `Control Module
<control.html>`_ if you're new to Stem and looking to get started.

With that aside, these can still be used for raw socket communication with
Tor...

::

  import asyncio
  import sys

  import stem.connection
  import stem.socket

  async def print_version() -> None:
    try:
      control_socket = stem.socket.ControlPort(port = 9051)
      await control_socket.connect()
      await stem.connection.authenticate(control_socket)
    except stem.SocketError as exc:
      print(f'Unable to connect to tor on port 9051: {exc}')
      sys.exit(1)
    except stem.connection.AuthenticationFailure as exc:
      print(f'Unable to authenticate: {exc}')
      sys.exit(1)

    print("Issuing 'GETINFO version' query...\\n")
    await control_socket.send('GETINFO version')
    print(await control_socket.recv())


  if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    try:
      loop.run_until_complete(print_version())
    finally:
      loop.close()

::

  % python example.py
  Issuing 'GETINFO version' query...

  version=0.4.3.5
  OK

**Module Overview:**

::

  BaseSocket - Thread safe socket.
    |- RelaySocket - Socket for a relay's ORPort.
    |  |- send - sends a message to the socket
    |  +- recv - receives a response from the socket
    |
    |- ControlSocket - Socket wrapper that speaks the tor control protocol.
    |  |- ControlPort - Control connection via a port.
    |  |- ControlSocketFile - Control connection via a local file socket.
    |  |
    |  |- send - sends a message to the socket
    |  +- recv - receives a ControlMessage from the socket
    |
    |- is_alive - reports if the socket is known to be closed
    |- is_localhost - returns if the socket is for the local system or not
    |- connection_time - timestamp when socket last connected or disconnected
    |- connect - connects a new socket
    +- close - shuts down the socket

  send_message - Writes a message to a control socket.
  recv_message - Reads a ControlMessage from a control socket.
  recv_message_from_bytes_io - Reads a ControlMessage from an I/O stream.
  send_formatting - Performs the formatting expected from sent messages.
"""

import asyncio
import re
import socket
import ssl
import sys
import time

import stem.response
import stem.util.str_tools

from stem.util import log
from types import TracebackType
from typing import Awaitable, BinaryIO, Callable, List, Optional, Tuple, Type, Union, overload

MESSAGE_PREFIX = re.compile(b'^[a-zA-Z0-9]{3}[-+ ]')
ERROR_MSG = 'Error while receiving a control message (%s): %s'

# lines to limit our trace logging to, you can disable this by setting it to None

TRUNCATE_LOGS = 10


class BaseSocket(object):
  """
  Thread safe socket, providing common socket functionality.
  """

  def __init__(self) -> None:
    self._reader = None  # type: Optional[asyncio.StreamReader]
    self._writer = None  # type: Optional[asyncio.StreamWriter]
    self._is_alive = False
    self._connection_time = 0.0  # time when we last connected or disconnected

    # The class is often initialized in a thread with an event loop different
    # from one where it will be used. The asyncio lock is bound to the loop
    # running in a thread where it is initialized. Therefore, we are creating
    # it in _get_send_lock when it is used the first time.

    self._send_lock = None  # type: Optional[asyncio.Lock]

  def is_alive(self) -> bool:
    """
    Checks if the socket is known to be closed. We won't be aware if it is
    until we either use it or have explicitily shut it down.

    In practice a socket derived from a port knows about its disconnection
    after failing to receive data, whereas socket file derived connections
    know after either sending or receiving data.

    This means that to have reliable detection for when we're disconnected
    you need to continually pull from the socket (which is part of what the
    :class:`~stem.control.BaseController` does).

    :returns: **bool** that's **True** if our socket is connected and **False**
      otherwise
    """

    return self._is_alive

  def is_localhost(self) -> bool:
    """
    Returns if the connection is for the local system or not.

    :returns: **bool** that's **True** if the connection is for the local host
      and **False** otherwise
    """

    return False

  def connection_time(self) -> float:
    """
    Provides the unix timestamp for when our socket was either connected or
    disconnected. That is to say, the time we connected if we're currently
    connected and the time we disconnected if we're not connected.

    .. versionadded:: 1.3.0

    :returns: **float** for when we last connected or disconnected, zero if
      we've never connected
    """

    return self._connection_time

  async def connect(self) -> None:
    """
    Connects to a new socket, closing our previous one if we're already
    attached.

    :raises: :class:`stem.SocketError` if unable to make a socket
    """

    async with self._get_send_lock():
      # Closes the socket if we're currently attached to one. Once we're no
      # longer alive it'll be safe to acquire the recv lock because recv()
      # calls no longer block (raising SocketClosed instead).

      if self.is_alive():
        await self._close_wo_send_lock()

      self._reader, self._writer = await self._open_connection()
      self._is_alive = True
      self._connection_time = time.time()

      # It's possible for this to have a transient failure...
      # SocketError: [Errno 4] Interrupted system call
      #
      # It's safe to retry, so give it another try if it fails.

      try:
        await self._connect()
      except stem.SocketError:
        await self._connect()  # single retry

  async def close(self) -> None:
    """
    Shuts down the socket. If it's already closed then this is a no-op.
    """

    async with self._get_send_lock():
      await self._close_wo_send_lock()

  async def _close_wo_send_lock(self) -> None:
    # Function is idempotent with one exception: we notify _close() if this
    # is causing our is_alive() state to change.

    is_change = self.is_alive()

    if self._writer:
      self._writer.close()
      # `StreamWriter.wait_closed` was added in Python 3.7.
      if sys.version_info >= (3, 7):
        await self._writer.wait_closed()

    self._reader = None
    self._writer = None
    self._is_alive = False
    self._connection_time = time.time()

    if is_change:
      await self._close()

  async def _send(self, message: Union[bytes, str], handler: Callable[[asyncio.StreamWriter, Union[bytes, str]], Awaitable[None]]) -> None:
    """
    Send message in a thread safe manner.
    """

    async with self._get_send_lock():
      try:
        if not self.is_alive():
          raise stem.SocketClosed()

        await handler(self._writer, message)
      except stem.SocketClosed:
        # if send_message raises a SocketClosed then we should properly shut
        # everything down

        if self.is_alive():
          await self._close_wo_send_lock()

        raise

  @overload
  async def _recv(self, handler: Callable[[asyncio.StreamReader], Awaitable[bytes]]) -> bytes:
    ...

  @overload
  async def _recv(self, handler: Callable[[asyncio.StreamReader], Awaitable[stem.response.ControlMessage]]) -> stem.response.ControlMessage:
    ...

  async def _recv(self, handler):
    """
    Receives a message in a thread safe manner.
    """

    try:
      # makes a temporary reference to the _reader because connect()
      # and close() may set or unset it

      my_reader = self._reader

      if not my_reader:
        raise stem.SocketClosed()

      return await handler(my_reader)
    except stem.SocketClosed:
      if self.is_alive():
        await self.close()

      raise

  def _get_send_lock(self) -> asyncio.Lock:
    """
    The send lock is useful to classes that interact with us at a deep level
    because it's used to lock :func:`stem.socket.ControlSocket.connect` /
    :func:`stem.socket.BaseSocket.close`, and by extension our
    :func:`stem.socket.BaseSocket.is_alive` state changes.

    :returns: **asyncio.Lock** that governs sending messages to our socket
      and state changes
    """

    if self._send_lock is None:
      self._send_lock = asyncio.Lock()
    return self._send_lock

  async def __aenter__(self) -> 'stem.socket.BaseSocket':
    return self

  async def __aexit__(self, exit_type: Optional[Type[BaseException]], value: Optional[BaseException], traceback: Optional[TracebackType]):
    await self.close()

  async def _connect(self) -> None:
    """
    Connection callback that can be overwritten by subclasses and wrappers.
    """

    pass

  async def _close(self) -> None:
    """
    Disconnection callback that can be overwritten by subclasses and wrappers.
    """

    pass

  async def _open_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    raise NotImplementedError('Unsupported Operation: this should be implemented by the BaseSocket subclass')


class RelaySocket(BaseSocket):
  """
  `Link-level connection
  <https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt>`_ to a Tor
  relay.

  .. versionadded:: 1.7.0

  :var str address: address our socket connects to
  :var int port: ORPort our socket connects to
  """

  def __init__(self, address: str = '127.0.0.1', port: int = 9050) -> None:
    """
    RelaySocket constructor.

    :param address: ip address of the relay
    :param port: orport of the relay
    """

    super(RelaySocket, self).__init__()
    self.address = address
    self.port = port

  async def send(self, message: Union[str, bytes]) -> None:
    """
    Sends a message to the relay's ORPort.

    :param message: message to be formatted and sent to the socket

    :raises:
      * :class:`stem.SocketError` if a problem arises in using the socket
      * :class:`stem.SocketClosed` if the socket is known to be shut down
    """

    await self._send(message, _write_to_socket)

  async def recv(self, timeout: Optional[float] = None) -> bytes:
    """
    Receives a message from the relay.

    :param timeout: maxiumum number of seconds to await a response, this
      blocks indefinitely if **None**

    :returns: bytes for the message received

    :raises:
      * :class:`stem.ProtocolError` the content from the socket is malformed
      * :class:`stem.SocketClosed` if the socket closes before we receive a complete message
    """

    async def wrapped_recv(reader: asyncio.StreamReader) -> Optional[bytes]:
      if timeout is None:
        return await reader.read(1024)
      else:
        try:
          return await asyncio.wait_for(reader.read(1024), max(timeout, 0.0001))
        except asyncio.TimeoutError:
          return None

    return await self._recv(wrapped_recv)

  def is_localhost(self) -> bool:
    return self.address == '127.0.0.1'

  async def _open_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
      return await asyncio.open_connection(self.address, self.port, ssl=ssl.SSLContext())
    except socket.error as exc:
      raise stem.SocketError(exc)


class ControlSocket(BaseSocket):
  """
  Wrapper for a socket connection that speaks the Tor control protocol. To the
  better part this transparently handles the formatting for sending and
  receiving complete messages.

  Callers should not instantiate this class directly, but rather use subclasses
  which are expected to implement the **_open_connection()** method.
  """

  def __init__(self) -> None:
    super(ControlSocket, self).__init__()

  async def send(self, message: Union[bytes, str]) -> None:
    """
    Formats and sends a message to the control socket. For more information see
    the :func:`~stem.socket.send_message` function.

    :param message: message to be formatted and sent to the socket

    :raises:
      * :class:`stem.SocketError` if a problem arises in using the socket
      * :class:`stem.SocketClosed` if the socket is known to be shut down
    """

    await self._send(message, send_message)

  async def recv(self) -> stem.response.ControlMessage:
    """
    Receives a message from the control socket, blocking until we've received
    one. For more information see the :func:`~stem.socket.recv_message` function.

    :returns: :class:`~stem.response.ControlMessage` for the message received

    :raises:
      * :class:`stem.ProtocolError` the content from the socket is malformed
      * :class:`stem.SocketClosed` if the socket closes before we receive a complete message
    """

    return await self._recv(recv_message)


class ControlPort(ControlSocket):
  """
  Control connection to tor. For more information see tor's ControlPort torrc
  option.

  :var str address: address our socket connects to
  :var int port: ControlPort our socket connects to
  """

  def __init__(self, address: str = '127.0.0.1', port: int = 9051) -> None:
    """
    ControlPort constructor.

    :param address: ip address of the controller
    :param port: port number of the controller
    """

    super(ControlPort, self).__init__()
    self.address = address
    self.port = port

  def is_localhost(self) -> bool:
    return self.address == '127.0.0.1'

  async def _open_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
      return await asyncio.open_connection(self.address, self.port)
    except socket.error as exc:
      raise stem.SocketError(exc)


class ControlSocketFile(ControlSocket):
  """
  Control connection to tor. For more information see tor's ControlSocket torrc
  option.

  :var str path: filesystem path of the socket we connect to
  """

  def __init__(self, path: str = '/var/run/tor/control') -> None:
    """
    ControlSocketFile constructor.

    :param path: path where the control socket is located
    """

    super(ControlSocketFile, self).__init__()
    self.path = path

  def is_localhost(self) -> bool:
    return True

  async def _open_connection(self) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
      return await asyncio.open_unix_connection(self.path)
    except socket.error as exc:
      raise stem.SocketError(exc)


async def send_message(writer: asyncio.StreamWriter, message: Union[bytes, str], raw: bool = False) -> None:
  """
  Sends a message to the control socket, adding the expected formatting for
  single verses multi-line messages. Neither message type should contain an
  ending newline (if so it'll be treated as a multi-line message with a blank
  line at the end). If the message doesn't contain a newline then it's sent
  as...

  ::

    <message>\\r\\n

  and if it does contain newlines then it's split on ``\\n`` and sent as...

  ::

    +<line 1>\\r\\n
    <line 2>\\r\\n
    <line 3>\\r\\n
    .\\r\\n

  :param writer: writer object
  :param message: message to be sent on the control socket
  :param raw: leaves the message formatting untouched, passing it to the
    socket as-is

  :raises:
    * :class:`stem.SocketError` if a problem arises in using the socket
    * :class:`stem.SocketClosed` if the socket is known to be shut down
  """

  message = stem.util.str_tools._to_unicode(message)

  if not raw:
    message = send_formatting(message)

  await _write_to_socket(writer, message)

  if log.is_tracing():
    log_message = message.replace('\r\n', '\n').rstrip()
    msg_div = '\n' if '\n' in log_message else ' '
    log.trace('Sent to tor:%s%s' % (msg_div, log_message))


async def _write_to_socket(writer: asyncio.StreamWriter, message: Union[str, bytes]) -> None:
  try:
    writer.write(stem.util.str_tools._to_bytes(message))
    await writer.drain()
  except socket.error as exc:
    log.info('Failed to send: %s' % exc)

    # When sending there doesn't seem to be a reliable method for
    # distinguishing between failures from a disconnect verses other things.
    # Just accounting for known disconnection responses.

    if str(exc) == '[Errno 32] Broken pipe':
      raise stem.SocketClosed(exc)
    else:
      raise stem.SocketError(exc)
  except AttributeError:
    # if the control_file has been closed then flush will receive:
    # AttributeError: 'NoneType' object has no attribute 'sendall'

    log.info('Failed to send: file has been closed')
    raise stem.SocketClosed('file has been closed')


async def recv_message(reader: asyncio.StreamReader, arrived_at: Optional[float] = None) -> stem.response.ControlMessage:
  """
  Pulls from a control socket until we either have a complete message or
  encounter a problem.

  :param reader: reader object

  :returns: :class:`~stem.response.ControlMessage` read from the socket

  :raises:
    * :class:`stem.ProtocolError` the content from the socket is malformed
    * :class:`stem.SocketClosed` if the socket closes before we receive
      a complete message
  """

  parsed_content = []  # type: List[Tuple[str, str, bytes]]
  raw_content = bytearray()
  first_line = True

  while True:
    try:
      line = await reader.readline()
    except AttributeError:
      # if the control_file has been closed then we will receive:
      # AttributeError: 'NoneType' object has no attribute 'recv'

      log.info(ERROR_MSG % ('SocketClosed', 'socket file has been closed'))
      raise stem.SocketClosed('socket file has been closed')
    except (OSError, ValueError) as exc:
      # when disconnected this errors with...
      #
      #   * ValueError: I/O operation on closed file
      #   * OSError: [Errno 107] Transport endpoint is not connected
      #   * OSError: [Errno 9] Bad file descriptor

      log.info(ERROR_MSG % ('SocketClosed', 'received exception "%s"' % exc))
      raise stem.SocketClosed(exc)

    # Parses the tor control lines. These are of the form...
    # <status code><divider><content>\r\n

    if not line:
      # if the socket is disconnected then the readline() method will provide
      # empty content

      log.info(ERROR_MSG % ('SocketClosed', 'empty socket content'))
      raise stem.SocketClosed('Received empty socket content.')
    elif not MESSAGE_PREFIX.match(line):
      log.info(ERROR_MSG % ('ProtocolError', 'malformed status code/divider, "%s"' % log.escape(line.decode('utf-8'))))
      raise stem.ProtocolError('Badly formatted reply line: beginning is malformed')
    elif not line.endswith(b'\r\n'):
      log.info(ERROR_MSG % ('ProtocolError', 'no CRLF linebreak, "%s"' % log.escape(line.decode('utf-8'))))
      raise stem.ProtocolError('All lines should end with CRLF')

    status_code, divider, content = line[:3], line[3:4], line[4:-2]  # strip CRLF off content

    status_code = stem.util.str_tools._to_unicode(status_code)
    divider = stem.util.str_tools._to_unicode(divider)

    # Most controller responses are single lines, in which case we don't need
    # so much overhead.

    if first_line:
      if divider == ' ':
        _log_trace(line)
        return stem.response.ControlMessage([(status_code, divider, content)], line, arrived_at = arrived_at)
      else:
        parsed_content, raw_content, first_line = [], bytearray(), False

    raw_content += line

    if divider == '-':
      # mid-reply line, keep pulling for more content
      parsed_content.append((status_code, divider, content))
    elif divider == ' ':
      # end of the message, return the message
      parsed_content.append((status_code, divider, content))
      _log_trace(bytes(raw_content))
      return stem.response.ControlMessage(parsed_content, bytes(raw_content), arrived_at = arrived_at)
    elif divider == '+':
      # data entry, all of the following lines belong to the content until we
      # get a line with just a period

      content_block = bytearray(content)

      while True:
        try:
          line = await reader.readline()
          raw_content += line
        except socket.error as exc:
          log.info(ERROR_MSG % ('SocketClosed', 'received an exception while mid-way through a data reply (exception: "%s", read content: "%s")' % (exc, log.escape(bytes(raw_content).decode('utf-8')))))
          raise stem.SocketClosed(exc)

        if not line.endswith(b'\r\n'):
          log.info(ERROR_MSG % ('ProtocolError', 'CRLF linebreaks missing from a data reply, "%s"' % log.escape(bytes(raw_content).decode('utf-8'))))
          raise stem.ProtocolError('All lines should end with CRLF')
        elif line == b'.\r\n':
          break  # data block termination

        line = line[:-2]  # strips off the CRLF

        # lines starting with a period are escaped by a second period (as per
        # section 2.4 of the control-spec)

        if line.startswith(b'..'):
          line = line[1:]

        content_block += b'\n' + line

      # joins the content using a newline rather than CRLF separator (more
      # conventional for multi-line string content outside the windows world)

      parsed_content.append((status_code, divider, bytes(content_block)))
    else:
      # this should never be reached due to the prefix regex, but might as well
      # be safe...

      log.warn(ERROR_MSG % ('ProtocolError', "\"%s\" isn't a recognized divider type" % divider))
      raise stem.ProtocolError("Unrecognized divider type '%s': %s" % (divider, stem.util.str_tools._to_unicode(line)))


def recv_message_from_bytes_io(reader: BinaryIO, arrived_at: Optional[float] = None) -> stem.response.ControlMessage:
  """
  Pulls from an I/O stream until we either have a complete message or
  encounter a problem.

  :param file reader: I/O stream

  :returns: :class:`~stem.response.ControlMessage` read from the socket

  :raises:
    * :class:`stem.ProtocolError` the content from the socket is malformed
    * :class:`stem.SocketClosed` if the socket closes before we receive
      a complete message
  """

  # TODO: We should deduplicate this with recv_message(), but separating IO
  # from the low level aspects of this parsing will be difficult.

  parsed_content = []  # type: List[Tuple[str, str, bytes]]
  raw_content = bytearray()
  first_line = True

  while True:
    try:
      line = reader.readline()
    except AttributeError:
      # if the control_file has been closed then we will receive:
      # AttributeError: 'NoneType' object has no attribute 'recv'

      log.info(ERROR_MSG % ('SocketClosed', 'socket file has been closed'))
      raise stem.SocketClosed('socket file has been closed')
    except (OSError, ValueError) as exc:
      # when disconnected this errors with...
      #
      #   * ValueError: I/O operation on closed file
      #   * OSError: [Errno 107] Transport endpoint is not connected
      #   * OSError: [Errno 9] Bad file descriptor

      log.info(ERROR_MSG % ('SocketClosed', 'received exception "%s"' % exc))
      raise stem.SocketClosed(exc)

    # Parses the tor control lines. These are of the form...
    # <status code><divider><content>\r\n

    if not line:
      # if the socket is disconnected then the readline() method will provide
      # empty content

      log.info(ERROR_MSG % ('SocketClosed', 'empty socket content'))
      raise stem.SocketClosed('Received empty socket content.')
    elif not MESSAGE_PREFIX.match(line):
      log.info(ERROR_MSG % ('ProtocolError', 'malformed status code/divider, "%s"' % log.escape(line.decode('utf-8'))))
      raise stem.ProtocolError('Badly formatted reply line: beginning is malformed')
    elif not line.endswith(b'\r\n'):
      log.info(ERROR_MSG % ('ProtocolError', 'no CRLF linebreak, "%s"' % log.escape(line.decode('utf-8'))))
      raise stem.ProtocolError('All lines should end with CRLF')

    status_code, divider, content = line[:3], line[3:4], line[4:-2]  # strip CRLF off content

    status_code = stem.util.str_tools._to_unicode(status_code)
    divider = stem.util.str_tools._to_unicode(divider)

    # Most controller responses are single lines, in which case we don't need
    # so much overhead.

    if first_line:
      if divider == ' ':
        _log_trace(line)
        return stem.response.ControlMessage([(status_code, divider, content)], line, arrived_at = arrived_at)
      else:
        parsed_content, raw_content, first_line = [], bytearray(), False

    raw_content += line

    if divider == '-':
      # mid-reply line, keep pulling for more content
      parsed_content.append((status_code, divider, content))
    elif divider == ' ':
      # end of the message, return the message
      parsed_content.append((status_code, divider, content))
      _log_trace(bytes(raw_content))
      return stem.response.ControlMessage(parsed_content, bytes(raw_content), arrived_at = arrived_at)
    elif divider == '+':
      # data entry, all of the following lines belong to the content until we
      # get a line with just a period

      content_block = bytearray(content)

      while True:
        try:
          line = reader.readline()
          raw_content += line
        except socket.error as exc:
          log.info(ERROR_MSG % ('SocketClosed', 'received an exception while mid-way through a data reply (exception: "%s", read content: "%s")' % (exc, log.escape(bytes(raw_content).decode('utf-8')))))
          raise stem.SocketClosed(exc)

        if not line.endswith(b'\r\n'):
          log.info(ERROR_MSG % ('ProtocolError', 'CRLF linebreaks missing from a data reply, "%s"' % log.escape(bytes(raw_content).decode('utf-8'))))
          raise stem.ProtocolError('All lines should end with CRLF')
        elif line == b'.\r\n':
          break  # data block termination

        line = line[:-2]  # strips off the CRLF

        # lines starting with a period are escaped by a second period (as per
        # section 2.4 of the control-spec)

        if line.startswith(b'..'):
          line = line[1:]

        content_block += b'\n' + line

      # joins the content using a newline rather than CRLF separator (more
      # conventional for multi-line string content outside the windows world)

      parsed_content.append((status_code, divider, bytes(content_block)))
    else:
      # this should never be reached due to the prefix regex, but might as well
      # be safe...

      log.warn(ERROR_MSG % ('ProtocolError', "\"%s\" isn't a recognized divider type" % divider))
      raise stem.ProtocolError("Unrecognized divider type '%s': %s" % (divider, stem.util.str_tools._to_unicode(line)))


def send_formatting(message: str) -> str:
  """
  Performs the formatting expected from sent control messages. For more
  information see the :func:`~stem.socket.send_message` function.

  :param message: message to be formatted

  :returns: **str** of the message wrapped by the formatting expected from
    controllers
  """

  # From control-spec section 2.2...
  #   Command = Keyword OptArguments CRLF / "+" Keyword OptArguments CRLF CmdData
  #   Keyword = 1*ALPHA
  #   OptArguments = [ SP *(SP / VCHAR) ]
  #
  # A command is either a single line containing a Keyword and arguments, or a
  # multiline command whose initial keyword begins with +, and whose data
  # section ends with a single "." on a line of its own.

  # if we already have \r\n entries then standardize on \n to start with
  message = message.replace('\r\n', '\n')

  if '\n' in message:
    return '+%s\r\n.\r\n' % message.replace('\n', '\r\n')
  else:
    return message + '\r\n'


def _log_trace(response: bytes) -> None:
  if not log.is_tracing():
    return

  log_message = stem.util.str_tools._to_unicode(response.replace(b'\r\n', b'\n').rstrip())
  log_message_lines = log_message.split('\n')

  if TRUNCATE_LOGS and len(log_message_lines) > TRUNCATE_LOGS:
    log_message = '\n'.join(log_message_lines[:TRUNCATE_LOGS] + ['... %i more lines...' % (len(log_message_lines) - TRUNCATE_LOGS)])

  if len(log_message_lines) > 2:
    log.trace('Received from tor:\n%s' % log_message)
  else:
    log.trace('Received from tor: %s' % log_message.replace('\n', '\\n'))
