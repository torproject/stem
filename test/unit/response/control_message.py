"""
Unit tests for the stem.response.ControlMessage parsing and class.
"""

import socket
import unittest

try:
  from StringIO import StringIO
except:
  from io import StringIO

import stem.socket
import stem.response
import stem.response.getinfo

OK_REPLY = '250 OK\r\n'

EVENT_BW = '650 BW 32326 2856\r\n'
EVENT_CIRC_TIMEOUT = '650 CIRC 5 FAILED PURPOSE=GENERAL REASON=TIMEOUT\r\n'
EVENT_CIRC_LAUNCHED = '650 CIRC 9 LAUNCHED PURPOSE=GENERAL\r\n'
EVENT_CIRC_EXTENDED = '650 CIRC 5 EXTENDED $A200F527C82C59A25CCA44884B49D3D65B122652=faktor PURPOSE=MEASURE_TIMEOUT\r\n'

GETINFO_VERSION = """250-version=0.2.2.23-alpha (git-b85eb949b528f4d7)
250 OK
""".replace('\n', '\r\n')

GETINFO_INFONAMES = """250+info/names=
accounting/bytes -- Number of bytes read/written so far in the accounting interval.
accounting/bytes-left -- Number of bytes left to write/read so far in the accounting interval.
accounting/enabled -- Is accounting currently enabled?
accounting/hibernating -- Are we hibernating or awake?
stream-status -- List of current streams.
version -- The current version of Tor.
.
250 OK
""".replace('\n', '\r\n')


class TestControlMessage(unittest.TestCase):
  def test_from_str(self):
    msg = stem.response.ControlMessage.from_str(GETINFO_VERSION)

    self.assertTrue(isinstance(msg, stem.response.ControlMessage))
    self.assertEqual('version=0.2.2.23-alpha (git-b85eb949b528f4d7)\nOK', str(msg))

    msg = stem.response.ControlMessage.from_str(GETINFO_VERSION, 'GETINFO')
    self.assertTrue(isinstance(msg, stem.response.getinfo.GetInfoResponse))
    self.assertEqual({'version': b'0.2.2.23-alpha (git-b85eb949b528f4d7)'}, msg.entries)

  def test_ok_response(self):
    """
    Checks the basic 'OK' response that we get for most commands.
    """

    message = self._assert_message_parses(OK_REPLY)
    self.assertEqual('OK', str(message))

    contents = message.content()
    self.assertEqual(1, len(contents))
    self.assertEqual(('250', ' ', 'OK'), contents[0])

  def test_event_response(self):
    """
    Checks parsing of actual events.
    """

    # BW event
    message = self._assert_message_parses(EVENT_BW)
    self.assertEqual('BW 32326 2856', str(message))

    contents = message.content()
    self.assertEqual(1, len(contents))
    self.assertEqual(('650', ' ', 'BW 32326 2856'), contents[0])

    # few types of CIRC events
    for circ_content in (EVENT_CIRC_TIMEOUT, EVENT_CIRC_LAUNCHED, EVENT_CIRC_EXTENDED):
      message = self._assert_message_parses(circ_content)
      self.assertEqual(circ_content[4:-2], str(message))

      contents = message.content()
      self.assertEqual(1, len(contents))
      self.assertEqual(('650', ' ', str(message)), contents[0])

  def test_getinfo_response(self):
    """
    Checks parsing of actual GETINFO responses.
    """

    # GETINFO version (basic single-line results)
    message = self._assert_message_parses(GETINFO_VERSION)
    self.assertEqual(2, len(list(message)))
    self.assertEqual(2, len(str(message).splitlines()))

    # manually checks the contents
    contents = message.content()
    self.assertEqual(2, len(contents))
    self.assertEqual(('250', '-', 'version=0.2.2.23-alpha (git-b85eb949b528f4d7)'), contents[0])
    self.assertEqual(('250', ' ', 'OK'), contents[1])

    # GETINFO info/names (data entry)
    message = self._assert_message_parses(GETINFO_INFONAMES)
    self.assertEqual(2, len(list(message)))
    self.assertEqual(8, len(str(message).splitlines()))

    # manually checks the contents
    contents = message.content()
    self.assertEqual(2, len(contents))

    first_entry = (contents[0][0], contents[0][1], contents[0][2][:contents[0][2].find('\n')])
    self.assertEqual(('250', '+', 'info/names='), first_entry)
    self.assertEqual(('250', ' ', 'OK'), contents[1])

  def test_no_crlf(self):
    """
    Checks that we get a ProtocolError when we don't have both a carriage
    return and newline for line endings. This doesn't really check for
    newlines (since that's what readline would break on), but not the end of
    the world.
    """

    # Replaces each of the CRLF entries with just LF, confirming that this
    # causes a parsing error. This should test line endings for both data
    # entry parsing and non-data.

    infonames_lines = [line + '\n' for line in GETINFO_INFONAMES.splitlines()]

    for index, line in enumerate(infonames_lines):
      # replace the CRLF for the line
      infonames_lines[index] = line.rstrip('\r\n') + '\n'
      test_socket_file = StringIO(''.join(infonames_lines))
      self.assertRaises(stem.ProtocolError, stem.socket.recv_message, test_socket_file)

      # puts the CRLF back
      infonames_lines[index] = infonames_lines[index].rstrip('\n') + '\r\n'

    # sanity check the above test isn't broken due to leaving infonames_lines
    # with invalid data

    self._assert_message_parses(''.join(infonames_lines))

  def test_malformed_prefix(self):
    """
    Checks parsing for responses where the header is missing a digit or divider.
    """

    for index in range(len(EVENT_BW)):
      # makes test input with that character missing or replaced
      removal_test_input = EVENT_BW[:index] + EVENT_BW[index + 1:]
      replacement_test_input = EVENT_BW[:index] + '#' + EVENT_BW[index + 1:]

      if index < 4 or index >= (len(EVENT_BW) - 2):
        # dropping the character should cause an error if...
        # - this is part of the message prefix
        # - this is disrupting the line ending

        self.assertRaises(stem.ProtocolError, stem.socket.recv_message, StringIO(removal_test_input))
        self.assertRaises(stem.ProtocolError, stem.socket.recv_message, StringIO(replacement_test_input))
      else:
        # otherwise the data will be malformed, but this goes undetected
        self._assert_message_parses(removal_test_input)
        self._assert_message_parses(replacement_test_input)

  def test_disconnected_socket(self):
    """
    Tests when the read function is given a file derived from a disconnected
    socket.
    """

    control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    control_socket_file = control_socket.makefile()
    self.assertRaises(stem.SocketClosed, stem.socket.recv_message, control_socket_file)

  def _assert_message_parses(self, controller_reply):
    """
    Performs some basic sanity checks that a reply mirrors its parsed result.

    Returns:
      stem.response.ControlMessage for the given input
    """

    message = stem.socket.recv_message(StringIO(controller_reply))

    # checks that the raw_content equals the input value
    self.assertEqual(controller_reply, message.raw_content())

    # checks that the contents match the input
    message_lines = str(message).splitlines()
    controller_lines = controller_reply.split('\r\n')
    controller_lines.pop()  # the ControlMessage won't have a trailing newline

    while controller_lines:
      line = controller_lines.pop(0)

      # mismatching lines with just a period are probably data termination
      if line == '.' and (not message_lines or line != message_lines[0]):
        continue

      self.assertTrue(line.endswith(message_lines.pop(0)))

    return message
