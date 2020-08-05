# Copyright 2012-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parses replies from the control socket.

**Module Overview:**

::

  convert - translates a ControlMessage into a particular response subclass

  ControlMessage - Message that's read from the control socket.
    |- SingleLineResponse - Simple tor response only including a single line of information.
    |
    |- from_str - provides a ControlMessage for the given string
    |- is_ok - response had a 250 status
    |- content - provides the parsed message content
    +- raw_content - unparsed socket data

  ControlLine - String subclass with methods for parsing controller responses.
    |- remainder - provides the unparsed content
    |- is_empty - checks if the remaining content is empty
    |- is_next_quoted - checks if the next entry is a quoted value
    |- is_next_mapping - checks if the next entry is a KEY=VALUE mapping
    |- peek_key - provides the key of the next entry
    |- pop - removes and returns the next entry
    +- pop_mapping - removes and returns the next entry as a KEY=VALUE mapping
"""

import codecs
import io
import re
import time
import threading

import stem.socket
import stem.util
import stem.util.str_tools

from typing import Any, Iterator, List, Optional, Sequence, Tuple, Union

__all__ = [
  'add_onion',
  'events',
  'getinfo',
  'getconf',
  'onion_client_auth',
  'protocolinfo',
  'authchallenge',
  'convert',
  'ControlMessage',
  'ControlLine',
  'SingleLineResponse',
]

KEY_ARG = re.compile('^(\\S+)=')


def convert(response_type: str, message: 'stem.response.ControlMessage', **kwargs: Any) -> None:
  """
  Converts a :class:`~stem.response.ControlMessage` into a particular kind of
  tor response. This does an in-place conversion of the message from being a
  :class:`~stem.response.ControlMessage` to a subclass for its response type.
  Recognized types include...

  =================== =====
  response_type       Class
  =================== =====
  **ADD_ONION**                :class:`stem.response.add_onion.AddOnionResponse`
  **AUTHCHALLENGE**            :class:`stem.response.authchallenge.AuthChallengeResponse`
  **EVENT**                    :class:`stem.response.events.Event` subclass
  **GETCONF**                  :class:`stem.response.getconf.GetConfResponse`
  **GETINFO**                  :class:`stem.response.getinfo.GetInfoResponse`
  **MAPADDRESS**               :class:`stem.response.mapaddress.MapAddressResponse`
  **ONION_CLIENT_AUTH_ADD**    :class:`stem.response.onion_client_auth.OnionClientAuthAddResponse`
  **ONION_CLIENT_AUTH_REMOVE** :class:`stem.response.onion_client_auth.OnionClientAuthRemoveResponse`
  **ONION_CLIENT_AUTH_VIEW**   :class:`stem.response.onion_client_auth.OnionClientAuthViewResponse`
  **PROTOCOLINFO**             :class:`stem.response.protocolinfo.ProtocolInfoResponse`
  **SINGLELINE**               :class:`stem.response.SingleLineResponse`
  =================== =====

  :param response_type: type of tor response to convert to
  :param message: message to be converted
  :param kwargs: optional keyword arguments to be passed to the parser method

  :raises:
    * :class:`stem.ProtocolError` the message isn't a proper response of
      that type
    * :class:`stem.InvalidArguments` the arguments given as input are
      invalid, this is can only be raised if the response_type is: **GETINFO**,
      **GETCONF**
    * :class:`stem.InvalidRequest` the arguments given as input are
      invalid, this is can only be raised if the response_type is:
      **MAPADDRESS**
    * :class:`stem.OperationFailed` if the action the event represents failed,
      this is can only be raised if the response_type is: **MAPADDRESS**
    * **TypeError** if argument isn't a :class:`~stem.response.ControlMessage`
      or response_type isn't supported
  """

  import stem.response.add_onion
  import stem.response.authchallenge
  import stem.response.events
  import stem.response.getinfo
  import stem.response.getconf
  import stem.response.mapaddress
  import stem.response.onion_client_auth
  import stem.response.protocolinfo

  if not isinstance(message, ControlMessage):
    raise TypeError('Only able to convert stem.response.ControlMessage instances')

  response_types = {
    'ADD_ONION': stem.response.add_onion.AddOnionResponse,
    'AUTHCHALLENGE': stem.response.authchallenge.AuthChallengeResponse,
    'EVENT': stem.response.events.Event,
    'GETCONF': stem.response.getconf.GetConfResponse,
    'GETINFO': stem.response.getinfo.GetInfoResponse,
    'MAPADDRESS': stem.response.mapaddress.MapAddressResponse,
    'ONION_CLIENT_AUTH_ADD': stem.response.onion_client_auth.OnionClientAuthAddResponse,
    'ONION_CLIENT_AUTH_REMOVE': stem.response.onion_client_auth.OnionClientAuthRemoveResponse,
    'ONION_CLIENT_AUTH_VIEW': stem.response.onion_client_auth.OnionClientAuthViewResponse,
    'PROTOCOLINFO': stem.response.protocolinfo.ProtocolInfoResponse,
    'SINGLELINE': SingleLineResponse,
  }

  try:
    response_class = response_types[response_type]
  except TypeError:
    raise TypeError('Unsupported response type: %s' % response_type)

  message.__class__ = response_class
  message._parse_message(**kwargs)  # type: ignore


# TODO: These aliases are for type hint compatability. We should refactor how
# message conversion is performed to avoid this headache.

def _convert_to_single_line(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.SingleLineResponse':
  stem.response.convert('SINGLELINE', message)
  return message  # type: ignore


def _convert_to_event(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.events.Event':
  stem.response.convert('EVENT', message)
  return message  # type: ignore


def _convert_to_getinfo(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.getinfo.GetInfoResponse':
  stem.response.convert('GETINFO', message)
  return message  # type: ignore


def _convert_to_getconf(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.getconf.GetConfResponse':
  stem.response.convert('GETCONF', message)
  return message  # type: ignore


def _convert_to_add_onion(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.add_onion.AddOnionResponse':
  stem.response.convert('ADD_ONION', message)
  return message  # type: ignore


def _convert_to_onion_client_auth_add(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.onion_client_auth.OnionClientAuthAddResponse':
  stem.response.convert('ONION_CLIENT_AUTH_ADD', message)
  return message  # type: ignore


def _convert_to_onion_client_auth_remove(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.onion_client_auth.OnionClientAuthRemoveResponse':
  stem.response.convert('ONION_CLIENT_AUTH_REMOVE', message)
  return message  # type: ignore


def _convert_to_onion_client_auth_view(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.onion_client_auth.OnionClientAuthViewResponse':
  stem.response.convert('ONION_CLIENT_AUTH_VIEW', message)
  return message  # type: ignore


def _convert_to_mapaddress(message: 'stem.response.ControlMessage', **kwargs: Any) -> 'stem.response.mapaddress.MapAddressResponse':
  stem.response.convert('MAPADDRESS', message)
  return message  # type: ignore


class ControlMessage(object):
  """
  Message from the control socket. This is iterable and can be stringified for
  individual message components stripped of protocol formatting. Messages are
  never empty.

  :var int arrived_at: unix timestamp for when the message arrived

  .. versionchanged:: 1.7.0
     Implemented equality and hashing.

  .. versionchanged:: 1.8.0
     Moved **arrived_at** from the Event class up to this base ControlMessage.
  """

  @staticmethod
  def from_str(content: Union[str, bytes], msg_type: Optional[str] = None, normalize: bool = False, **kwargs: Any) -> 'stem.response.ControlMessage':
    """
    Provides a ControlMessage for the given content.

    .. versionadded:: 1.1.0

    .. versionchanged:: 1.6.0
       Added the normalize argument.

    :param content: message to construct the message from
    :param msg_type: type of tor reply to parse the content as
    :param normalize: ensures expected carriage return and ending newline
      are present
    :param kwargs: optional keyword arguments to be passed to the parser method

    :returns: stem.response.ControlMessage instance
    """

    if isinstance(content, str):
      content = stem.util.str_tools._to_bytes(content)

    if normalize:
      if not content.endswith(b'\n'):
        content += b'\n'

      content = re.sub(b'([\r]?)\n', b'\r\n', content)

    msg = stem.socket.recv_message_from_bytes_io(io.BytesIO(stem.util.str_tools._to_bytes(content)), arrived_at = kwargs.pop('arrived_at', None))

    if msg_type is not None:
      convert(msg_type, msg, **kwargs)

    return msg

  def __init__(self, parsed_content: Sequence[Tuple[str, str, bytes]], raw_content: bytes, arrived_at: Optional[float] = None) -> None:
    if not parsed_content:
      raise ValueError("ControlMessages can't be empty")

    # TODO: Change arrived_at to a float (can't yet because it causes Event
    # equality checks to fail - events include arrived_at within their hash
    # whereas ControlMessages don't).

    self.arrived_at = int(arrived_at if arrived_at else time.time())

    self._parsed_content = parsed_content
    self._raw_content = raw_content
    self._str = None  # type: Optional[str]
    self._hash = stem.util._hash_attr(self, '_raw_content')

  def is_ok(self) -> bool:
    """
    Checks if any of our lines have a 250, 251 or 252 response.

    :returns: **True** if any lines have a 250, 251 or 252 response code, **False** otherwise
    """

    for code, _, _ in self._parsed_content:
      if code in ['250', '251', '252']:
        return True

    return False

  # TODO: drop this alias when we provide better type support

  def _content_bytes(self) -> List[Tuple[str, str, bytes]]:
    return self.content(get_bytes = True)  # type: ignore

  def content(self, get_bytes: bool = False) -> List[Tuple[str, str, str]]:
    """
    Provides the parsed message content. These are entries of the form...

    ::

      (status_code, divider, content)

    **status_code**
      Three character code for the type of response (defined in section 4 of
      the control-spec).

    **divider**
      Single character to indicate if this is mid-reply, data, or an end to the
      message (defined in section 2.3 of the control-spec).

    **content**
      The following content is the actual payload of the line.

    For data entries the content is the full multi-line payload with newline
    linebreaks and leading periods unescaped.

    The **status_code** and **divider** are both strings (**bytes** in python
    2.x and **unicode** in python 3.x). The **content** however is **bytes** if
    **get_bytes** is **True**.

    .. versionchanged:: 1.1.0
       Added the get_bytes argument.

    :param get_bytes: provides **bytes** for the **content** rather than a **str**

    :returns: **list** of (str, str, str) tuples for the components of this message
    """

    if not get_bytes:
      return [(code, div, stem.util.str_tools._to_unicode(content)) for (code, div, content) in self._parsed_content]
    else:
      return list(self._parsed_content)  # type: ignore

  def raw_content(self, get_bytes: bool = False) -> Union[str, bytes]:
    """
    Provides the unparsed content read from the control socket.

    .. versionchanged:: 1.1.0
       Added the get_bytes argument.

    :param get_bytes: if **True** then this provides **bytes** rather than a **str**

    :returns: **str** of the socket data used to generate this message
    """

    if not get_bytes:
      return stem.util.str_tools._to_unicode(self._raw_content)
    else:
      return self._raw_content

  def _parse_message(self) -> None:
    raise NotImplementedError('Implemented by subclasses')

  def __str__(self) -> str:
    """
    Content of the message, stripped of status code and divider protocol
    formatting.
    """

    if self._str is None:
      self._str = '\n'.join(list(self))

    return self._str

  def __iter__(self) -> Iterator['stem.response.ControlLine']:
    """
    Provides :class:`~stem.response.ControlLine` instances for the content of
    the message. This is stripped of status codes and dividers, for instance...

    ::

      250+info/names=
      desc/id/* -- Router descriptors by ID.
      desc/name/* -- Router descriptors by nickname.
      .
      250 OK

    Would provide two entries...

    ::

      1st - "info/names=
             desc/id/* -- Router descriptors by ID.
             desc/name/* -- Router descriptors by nickname."
      2nd - "OK"
    """

    for _, _, content in self._parsed_content:
      yield ControlLine(stem.util.str_tools._to_unicode(content))

  def __len__(self) -> int:
    """
    :returns: number of ControlLines
    """

    return len(self._parsed_content)

  def __getitem__(self, index: int) -> 'stem.response.ControlLine':
    """
    :returns: :class:`~stem.response.ControlLine` at the index
    """

    content = self._parsed_content[index][2]
    content = stem.util.str_tools._to_unicode(content)

    return ControlLine(content)

  def __hash__(self) -> int:
    return self._hash

  def __eq__(self, other: Any) -> bool:
    return hash(self) == hash(other) if isinstance(other, ControlMessage) else False

  def __ne__(self, other: Any) -> bool:
    return not self == other


class ControlLine(str):
  """
  String subclass that represents a line of controller output. This behaves as
  a normal string with additional methods for parsing and popping entries from
  a space delimited series of elements like a stack.

  None of these additional methods effect ourselves as a string (which is still
  immutable). All methods are thread safe.
  """

  def __new__(self, value: str) -> 'stem.response.ControlLine':
    return str.__new__(self, value)  # type: ignore

  def __init__(self, value: str) -> None:
    self._remainder = value
    self._remainder_lock = threading.RLock()

  def remainder(self) -> str:
    """
    Provides our unparsed content. This is an empty string after we've popped
    all entries.

    :returns: **str** of the unparsed content
    """

    return self._remainder

  def is_empty(self) -> bool:
    """
    Checks if we have further content to pop or not.

    :returns: **True** if we have additional content, **False** otherwise
    """

    return self._remainder == ''

  def is_next_quoted(self, escaped: bool = False) -> bool:
    """
    Checks if our next entry is a quoted value or not.

    :param escaped: unescapes the string

    :returns: **True** if the next entry can be parsed as a quoted value, **False** otherwise
    """

    start_quote, end_quote = _get_quote_indices(self._remainder, escaped)
    return start_quote == 0 and end_quote != -1

  def is_next_mapping(self, key: Optional[str] = None, quoted: bool = False, escaped: bool = False) -> bool:
    """
    Checks if our next entry is a KEY=VALUE mapping or not.

    :param key: checks that the key matches this value, skipping the check if **None**
    :param quoted: checks that the mapping is to a quoted value
    :param escaped: unescapes the string

    :returns: **True** if the next entry can be parsed as a key=value mapping,
      **False** otherwise
    """

    remainder = self._remainder  # temp copy to avoid locking
    key_match = KEY_ARG.match(remainder)

    if key_match:
      if key and key != key_match.groups()[0]:
        return False

      if quoted:
        # checks that we have a quoted value and that it comes after the 'key='
        start_quote, end_quote = _get_quote_indices(remainder, escaped)
        return start_quote == key_match.end() and end_quote != -1
      else:
        return True  # we just needed to check for the key
    else:
      return False  # doesn't start with a key

  def peek_key(self) -> str:
    """
    Provides the key of the next entry, providing **None** if it isn't a
    key/value mapping.

    :returns: **str** with the next entry's key
    """

    remainder = self._remainder
    key_match = KEY_ARG.match(remainder)

    if key_match:
      return key_match.groups()[0]
    else:
      return None

  def pop(self, quoted: bool = False, escaped: bool = False) -> str:
    """
    Parses the next space separated entry, removing it and the space from our
    remaining content. Examples...

    ::

      >>> line = ControlLine("\\"We're all mad here.\\" says the grinning cat.")
      >>> print line.pop(True)
        "We're all mad here."
      >>> print line.pop()
        "says"
      >>> print line.remainder()
        "the grinning cat."

      >>> line = ControlLine("\\"this has a \\\\\\" and \\\\\\\\ in it\\" foo=bar more_data")
      >>> print line.pop(True, True)
        "this has a \\" and \\\\ in it"

    :param quoted: parses the next entry as a quoted value, removing the quotes
    :param escaped: unescapes the string

    :returns: **str** of the next space separated entry

    :raises:
      * **ValueError** if quoted is True without the value being quoted
      * **IndexError** if we don't have any remaining content left to parse
    """

    with self._remainder_lock:
      next_entry, remainder = _parse_entry(self._remainder, quoted, escaped, False)
      self._remainder = remainder
      return next_entry  # type: ignore

  # TODO: drop this alias when we provide better type support

  def _pop_mapping_bytes(self, quoted: bool = False, escaped: bool = False) -> Tuple[str, bytes]:
    return self.pop_mapping(quoted, escaped, get_bytes = True)  # type: ignore

  def pop_mapping(self, quoted: bool = False, escaped: bool = False, get_bytes: bool = False) -> Tuple[str, str]:
    """
    Parses the next space separated entry as a KEY=VALUE mapping, removing it
    and the space from our remaining content.

    .. versionchanged:: 1.6.0
       Added the get_bytes argument.

    :param quoted: parses the value as being quoted, removing the quotes
    :param escaped: unescapes the string
    :param get_bytes: provides **bytes** for the **value** rather than a **str**

    :returns: **tuple** of the form (key, value)

    :raises: **ValueError** if this isn't a KEY=VALUE mapping or if quoted is
      **True** without the value being quoted
    :raises: **IndexError** if there's nothing to parse from the line
    """

    with self._remainder_lock:
      if self.is_empty():
        raise IndexError('no remaining content to parse')

      key_match = KEY_ARG.match(self._remainder)

      if not key_match:
        raise ValueError("the next entry isn't a KEY=VALUE mapping: " + self._remainder)

      # parse off the key
      key = key_match.groups()[0]
      remainder = self._remainder[key_match.end():]

      next_entry, remainder = _parse_entry(remainder, quoted, escaped, get_bytes)
      self._remainder = remainder
      return (key, next_entry)  # type: ignore


def _parse_entry(line: str, quoted: bool, escaped: bool, get_bytes: bool) -> Tuple[Union[str, bytes], str]:
  """
  Parses the next entry from the given space separated content.

  :param line: content to be parsed
  :param quoted: parses the next entry as a quoted value, removing the quotes
  :param escaped: unescapes the string
  :param get_bytes: provides **bytes** for the entry rather than a **str**

  :returns: **tuple** of the form (entry, remainder)

  :raises:
    * **ValueError** if quoted is True without the next value being quoted
    * **IndexError** if there's nothing to parse from the line
  """

  if line == '':
    raise IndexError('no remaining content to parse')

  next_entry, remainder = '', line

  if quoted:
    # validate and parse the quoted value
    start_quote, end_quote = _get_quote_indices(remainder, escaped)

    if start_quote != 0 or end_quote == -1:
      raise ValueError("the next entry isn't a quoted value: " + line)

    next_entry, remainder = remainder[1:end_quote], remainder[end_quote + 1:]
  else:
    # non-quoted value, just need to check if there's more data afterward
    if ' ' in remainder:
      next_entry, remainder = remainder.split(' ', 1)
    else:
      next_entry, remainder = remainder, ''

  if escaped:
    # Tor does escaping in its 'esc_for_log' function of 'common/util.c'. It's
    # hard to tell what controller functions use this in practice, but direct
    # users are...
    #
    #   * 'COOKIEFILE' field of PROTOCOLINFO responses
    #   * logged messages about bugs
    #   * the 'getinfo_helper_listeners' function of control.c
    #
    # Ideally we'd use "next_entry.decode('string_escape')" but it was removed
    # in python 3.x and 'unicode_escape' isn't quite the same...
    #
    #   https://stackoverflow.com/questions/14820429/how-do-i-decodestring-escape-in-python3

    next_entry = codecs.escape_decode(next_entry)[0]  # type: ignore

    if not get_bytes:
      next_entry = stem.util.str_tools._to_unicode(next_entry)  # normalize back to str

  if get_bytes:
    return (stem.util.str_tools._to_bytes(next_entry), remainder.lstrip())
  else:
    return (next_entry, remainder.lstrip())


def _get_quote_indices(line: str, escaped: bool) -> Tuple[int, int]:
  """
  Provides the indices of the next two quotes in the given content.

  :param line: content to be parsed
  :param escaped: unescapes the string

  :returns: **tuple** of two ints, indices being -1 if a quote doesn't exist
  """

  indices, quote_index = [], -1

  for _ in range(2):
    quote_index = line.find('"', quote_index + 1)

    # if we have escapes then we need to skip any r'\"' entries
    if escaped:
      # skip check if index is -1 (no match) or 0 (first character)
      while quote_index >= 1 and line[quote_index - 1] == '\\':
        quote_index = line.find('"', quote_index + 1)

    indices.append(quote_index)

  return tuple(indices)  # type: ignore


class SingleLineResponse(ControlMessage):
  """
  Reply to a request that performs an action rather than querying data. These
  requests only contain a single line, which is 'OK' if successful, and a
  description of the problem if not.

  :var str code: status code for our line
  :var str message: content of the line
  """

  def is_ok(self, strict: bool = False) -> bool:
    """
    Checks if the response code is "250". If strict is **True** then this
    checks if the response is "250 OK"

    :param strict: checks for a "250 OK" message if **True**

    :returns:
      * If strict is **False**: **True** if the response code is "250", **False** otherwise
      * If strict is **True**: **True** if the response is "250 OK", **False** otherwise
    """

    if strict:
      return self.content()[0] == ('250', ' ', 'OK')

    return self.content()[0][0] == '250'

  def _parse_message(self) -> None:
    content = self.content()

    if len(content) > 1:
      raise stem.ProtocolError('Received multi-line response')
    elif len(content) == 0:
      raise stem.ProtocolError('Received empty response')
    else:
      code, _, msg = content[0]

      self.code = stem.util.str_tools._to_unicode(code)
      self.message = stem.util.str_tools._to_unicode(msg)
