# Copyright 2012-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Toolkit for various string activity.

**Module Overview:**

::

  crop - shortens string to a given length

  size_label - human readable label for a number of bytes
  time_label - human readable label for a number of seconds
  time_labels - human readable labels for each time unit
  short_time_label - condensed time label output
  parse_short_time_label - seconds represented by a short time label
"""

import base64
import codecs
import datetime
import re
import sys

import stem.util
import stem.util.enum

from typing import List, Optional, Sequence, Tuple, Union, overload

# label conversion tuples of the form...
# (bits / bytes / seconds, short label, long label)

SIZE_UNITS_BITS = (
  (140737488355328.0, ' Pb', ' Petabit'),
  (137438953472.0, ' Tb', ' Terabit'),
  (134217728.0, ' Gb', ' Gigabit'),
  (131072.0, ' Mb', ' Megabit'),
  (128.0, ' Kb', ' Kilobit'),
  (0.125, ' b', ' Bit'),
)

SIZE_UNITS_BYTES = (
  (1125899906842624.0, ' PB', ' Petabyte'),
  (1099511627776.0, ' TB', ' Terabyte'),
  (1073741824.0, ' GB', ' Gigabyte'),
  (1048576.0, ' MB', ' Megabyte'),
  (1024.0, ' KB', ' Kilobyte'),
  (1.0, ' B', ' Byte'),
)

TIME_UNITS = (
  (86400.0, 'd', ' day'),
  (3600.0, 'h', ' hour'),
  (60.0, 'm', ' minute'),
  (1.0, 's', ' second'),
)

_timestamp_re = re.compile(r'(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})')


def _to_bytes(msg: Union[str, bytes]) -> bytes:
  """
  Provides the ASCII bytes for the given string. This is purely to provide
  python 3 compatability, normalizing the unicode/ASCII change in the version
  bump. For an explanation of this see...

  http://python3porting.com/problems.html#nicer-solutions

  :param msg: string to be converted

  :returns: ASCII bytes for string
  """

  if isinstance(msg, str):
    return codecs.latin_1_encode(msg, 'replace')[0]  # type: ignore
  else:
    return msg


def _to_unicode(msg: Union[str, bytes]) -> str:
  """
  Provides the unicode string for the given ASCII bytes. This is purely to
  provide python 3 compatability, normalizing the unicode/ASCII change in the
  version bump.

  :param msg: string to be converted

  :returns: unicode conversion
  """

  if msg is not None and not isinstance(msg, str):
    return msg.decode('utf-8', 'replace')
  else:
    return msg


def _decode_b64(msg: bytes) -> bytes:
  """
  Base64 decode, without padding concerns.
  """

  missing_padding = len(msg) % 4
  padding_chr = b'=' if isinstance(msg, bytes) else '='

  return base64.b64decode(msg + (padding_chr * missing_padding))


def _to_int(msg: Union[str, bytes]) -> int:
  """
  Serializes a string to a number.

  :param msg: string to be serialized

  :returns: **int** representation of the string
  """

  if isinstance(msg, bytes):
    # iterating over bytes in python3 provides ints rather than characters
    return sum([pow(256, (len(msg) - i - 1)) * c for (i, c) in enumerate(msg)])
  else:
    return sum([pow(256, (len(msg) - i - 1)) * ord(c) for (i, c) in enumerate(msg)])


def _to_camel_case(label: str, divider: str = '_', joiner: str = ' ') -> str:
  """
  Converts the given string to camel case, ie:

  ::

    >>> _to_camel_case('I_LIKE_PEPPERJACK!')
    'I Like Pepperjack!'

  :param label: input string to be converted
  :param divider: word boundary
  :param joiner: replacement for word boundaries

  :returns: camel cased string
  """

  words = []
  for entry in label.split(divider):
    if len(entry) == 0:
      words.append('')
    elif len(entry) == 1:
      words.append(entry.upper())
    else:
      words.append(entry[0].upper() + entry[1:].lower())

  return joiner.join(words)


@overload
def _split_by_length(msg: bytes, size: int) -> List[bytes]:
  ...


@overload
def _split_by_length(msg: str, size: int) -> List[str]:
  ...


def _split_by_length(msg, size):
  """
  Splits a string into a list of strings up to the given size.

  ::

    >>> _split_by_length('hello', 2)
    ['he', 'll', 'o']

  :param msg: string to split
  :param size: number of characters to chunk into

  :returns: **list** with chunked string components
  """

  return [msg[i:i + size] for i in range(0, len(msg), size)]


# This needs to be defined after _to_camel_case() to avoid a circular
# dependency with the enum module.

Ending = stem.util.enum.Enum('ELLIPSE', 'HYPHEN')


def crop(msg: str, size: int, min_word_length: int = 4, min_crop: int = 0, ending: 'stem.util.str_tools.Ending' = Ending.ELLIPSE, get_remainder: bool = False) -> Union[str, Tuple[str, str]]:
  """
  Shortens a string to a given length.

  If we crop content then a given ending is included (counting itself toward
  the size limitation). This crops on word breaks so we only include a word if
  we can display at least **min_word_length** characters of it.

  If there isn't room for even a truncated single word (or one word plus the
  ellipse if including those) then this provides an empty string.

  If a cropped string ends with a comma or period then it's stripped (unless
  we're providing the remainder back). For example...

    >>> crop('This is a looooong message', 17)
    'This is a looo...'

    >>> crop('This is a looooong message', 12)
    'This is a...'

    >>> crop('This is a looooong message', 3)
    ''

  The whole point of this method is to provide human friendly croppings, and as
  such details of how this works might change in the future. Callers should not
  rely on the details of how this crops.

  .. versionadded:: 1.3.0

  :param msg: text to be processed
  :param size: space available for text
  :param min_word_length: minimum characters before which a word is
    dropped, requires whole word if **None**
  :param min_crop: minimum characters that must be dropped if a word is
    cropped
  :param ending: type of ending used when truncating, no special
    truncation is used if **None**
  :param get_remainder: returns a tuple with the second part being the
    cropped portion of the message

  :returns: **str** of the text truncated to the given length
  """

  # checks if there's room for the whole message

  if len(msg) <= size:
    return (msg, '') if get_remainder else msg

  if size < 0:
    raise ValueError("Crop size can't be negative (received %i)" % size)
  elif min_word_length and min_word_length < 0:
    raise ValueError("Crop's min_word_length can't be negative (received %i)" % min_word_length)
  elif min_crop < 0:
    raise ValueError("Crop's min_crop can't be negative (received %i)" % min_crop)

  # since we're cropping, the effective space available is less with an
  # ellipse, and cropping words requires an extra space for hyphens

  if ending == Ending.ELLIPSE:
    if size < 3:
      return ('', msg) if get_remainder else ''

    size -= 3
  elif min_word_length and ending == Ending.HYPHEN:
    min_word_length += 1

  if min_word_length is None:
    min_word_length = sys.maxsize

  # checks if there isn't the minimum space needed to include anything

  last_wordbreak = msg.rfind(' ', 0, size + 1)

  if last_wordbreak == -1:
    # we're splitting the first word

    if size < min_word_length:
      return ('', msg) if get_remainder else ''

    include_crop = True
  else:
    last_wordbreak = len(msg[:last_wordbreak].rstrip())  # drops extra ending whitespaces
    include_crop = size - last_wordbreak - 1 >= min_word_length

  # if there's a max crop size then make sure we're cropping at least that many characters

  if include_crop and min_crop:
    next_wordbreak = msg.find(' ', size)

    if next_wordbreak == -1:
      next_wordbreak = len(msg)

    include_crop = next_wordbreak - size + 1 >= min_crop

  if include_crop:
    return_msg, remainder = msg[:size], msg[size:]

    if ending == Ending.HYPHEN:
      remainder = return_msg[-1] + remainder
      return_msg = return_msg[:-1].rstrip() + '-'
  else:
    return_msg, remainder = msg[:last_wordbreak], msg[last_wordbreak:]

  # if this is ending with a comma or period then strip it off

  if not get_remainder and return_msg and return_msg[-1] in (',', '.'):
    return_msg = return_msg[:-1]

  if ending == Ending.ELLIPSE:
    return_msg = return_msg.rstrip() + '...'

  return (return_msg, remainder) if get_remainder else return_msg


def size_label(byte_count: Union[int, float], decimal: int = 0, is_long: bool = False, is_bytes: bool = True, round: bool = False) -> str:
  """
  Converts a number of bytes into a human readable label in its most
  significant units. For instance, 7500 bytes would return "7 KB". If the
  is_long option is used this expands unit labels to be the properly pluralized
  full word (for instance 'Kilobytes' rather than 'KB'). Units go up through
  petabytes.

  ::

    >>> size_label(2000000)
    '1 MB'

    >>> size_label(1050, 2)
    '1.02 KB'

    >>> size_label(1050, 3, True)
    '1.025 Kilobytes'

  .. versionchanged:: 1.6.0
     Added round argument.

  :param byte_count: number of bytes to be converted
  :param decimal: number of decimal digits to be included
  :param is_long: expands units label
  :param is_bytes: provides units in bytes if **True**, bits otherwise
  :param round: rounds normally if **True**, otherwise rounds down

  :returns: **str** with human readable representation of the size
  """

  if is_bytes:
    return _get_label(SIZE_UNITS_BYTES, byte_count, decimal, is_long, round)
  else:
    return _get_label(SIZE_UNITS_BITS, byte_count, decimal, is_long, round)


def time_label(seconds: Union[int, float], decimal: int = 0, is_long: bool = False) -> str:
  """
  Converts seconds into a time label truncated to its most significant units.
  For instance, 7500 seconds would return "2h". Units go up through days.

  This defaults to presenting single character labels, but if the is_long
  option is used this expands labels to be the full word (space included and
  properly pluralized). For instance, "4h" would be "4 hours" and "1m" would
  become "1 minute".

  ::

    >>> time_label(10000)
    '2h'

    >>> time_label(61, 1, True)
    '1.0 minute'

    >>> time_label(61, 2, True)
    '1.01 minutes'

  :param seconds: number of seconds to be converted
  :param decimal: number of decimal digits to be included
  :param is_long: expands units label

  :returns: **str** with human readable representation of the time
  """

  return _get_label(TIME_UNITS, seconds, decimal, is_long)


def time_labels(seconds: Union[int, float], is_long: bool = False) -> Sequence[str]:
  """
  Provides a list of label conversions for each time unit, starting with its
  most significant units on down. Any counts that evaluate to zero are omitted.
  For example...

  ::

    >>> time_labels(400)
    ['6m', '40s']

    >>> time_labels(3640, True)
    ['1 hour', '40 seconds']

  :param seconds: number of seconds to be converted
  :param is_long: expands units label

  :returns: **list** of strings with human readable representations of the time
  """

  time_labels = []

  for count_per_unit, _, _ in TIME_UNITS:
    if abs(seconds) >= count_per_unit:
      time_labels.append(_get_label(TIME_UNITS, seconds, 0, is_long))
      seconds %= int(count_per_unit)

  return time_labels


def short_time_label(seconds: Union[int, float]) -> str:
  """
  Provides a time in the following format:
  [[dd-]hh:]mm:ss

  ::

    >>> short_time_label(111)
    '01:51'

    >>> short_time_label(544100)
    '6-07:08:20'

  :param seconds: number of seconds to be converted

  :returns: **str** with the short representation for the time

  :raises: **ValueError** if the input is negative
  """

  if seconds < 0:
    raise ValueError("Input needs to be a non-negative integer, got '%i'" % seconds)

  time_comp = {}

  for amount, _, label in TIME_UNITS:
    count = int(seconds / amount)
    seconds %= int(amount)
    time_comp[label.strip()] = count

  label = '%02i:%02i' % (time_comp['minute'], time_comp['second'])

  if time_comp['day']:
    label = '%i-%02i:%s' % (time_comp['day'], time_comp['hour'], label)
  elif time_comp['hour']:
    label = '%02i:%s' % (time_comp['hour'], label)

  return label


def parse_short_time_label(label: str) -> int:
  """
  Provides the number of seconds corresponding to the formatting used for the
  cputime and etime fields of ps:
  [[dd-]hh:]mm:ss or mm:ss.ss

  ::

    >>> parse_short_time_label('01:51')
    111

    >>> parse_short_time_label('6-07:08:20')
    544100

  :param label: time entry to be parsed

  :returns: **int** with the number of seconds represented by the label

  :raises: **ValueError** if input is malformed
  """

  days, hours, minutes, seconds = '0', '0', '0', '0'

  if '-' in label:
    days, label = label.split('-', 1)

  time_comp = label.split(':')

  if len(time_comp) == 3:
    hours, minutes, seconds = time_comp
  elif len(time_comp) == 2:
    minutes, seconds = time_comp
  else:
    raise ValueError("Invalid time format, we expected '[[dd-]hh:]mm:ss' or 'mm:ss.ss': %s" % label)

  try:
    time_sum = int(float(seconds))
    time_sum += int(minutes) * 60
    time_sum += int(hours) * 3600
    time_sum += int(days) * 86400
    return time_sum
  except ValueError:
    raise ValueError('Non-numeric value in time entry: %s' % label)


def _parse_timestamp(entry: str, tz: Optional[datetime.timezone]) -> datetime.datetime:
  """
  Parses the date and time that in format like like...

  ::

    2012-11-08 16:48:41

  :param entry: timestamp to be parsed
  :param tz: timezone of the entry (if **None**, the returned **datetime** will
    be "naive")

  :returns: **datetime** for the time represented by the timestamp

  :raises: **ValueError** if the timestamp is malformed
  """

  if not isinstance(entry, (bytes, str)):
    raise ValueError('parse_timestamp() input must be a str, got a %s' % type(entry))

  try:
    time = [int(x) for x in _timestamp_re.match(entry).groups()]
  except AttributeError:
    raise ValueError('Expected timestamp in format YYYY-MM-DD HH:MM:ss but got ' + entry)

  dt = datetime.datetime(time[0], time[1], time[2], time[3], time[4], time[5])

  if tz != None:
    dt.replace(tzinfo=tz)

  return dt


def _parse_iso_timestamp(entry: str) -> 'datetime.datetime':
  """
  Parses the ISO 8601 standard that provides for timestamps like...

  ::

    2012-11-08T16:48:41.420251

  :param entry: timestamp to be parsed

  :returns: **datetime** for the time represented by the timestamp

  :raises: **ValueError** if the timestamp is malformed
  """

  if not isinstance(entry, (bytes, str)):
    raise ValueError('parse_iso_timestamp() input must be a str, got a %s' % type(entry))

  # based after suggestions from...
  # http://stackoverflow.com/questions/127803/how-to-parse-iso-formatted-date-in-python

  if '.' in entry:
    timestamp_str, microseconds = entry.split('.')
  else:
    timestamp_str, microseconds = entry, '000000'

  if len(microseconds) != 6 or not microseconds.isdigit():
    raise ValueError("timestamp's microseconds should be six digits")

  if len(timestamp_str) > 10 and timestamp_str[10] == 'T':
    timestamp_str = timestamp_str[:10] + ' ' + timestamp_str[11:]
  else:
    raise ValueError("timestamp didn't contain delimeter 'T' between date and time")

  timestamp = _parse_timestamp(timestamp_str, datetime.timezone.utc)
  return timestamp + datetime.timedelta(microseconds = int(microseconds))


def _get_label(units: Sequence[Tuple[float, str, str]], count: Union[int, float], decimal: int, is_long: bool, round: bool = False) -> str:
  """
  Provides label corresponding to units of the highest significance in the
  provided set. This rounds down (ie, integer truncation after visible units).

  :param units: type of units to be used for conversion, containing
    (count_per_unit, short_label, long_label)
  :param count: number of base units being converted
  :param decimal: decimal precision of label
  :param is_long: uses the long label if **True**, short label otherwise
  :param round: rounds normally if **True**, otherwise rounds down
  """

  # formatted string for the requested number of digits
  label_format = '%%.%if' % decimal
  remainder = count

  if remainder < 0:
    label_format = '-' + label_format
    remainder = abs(remainder)
  elif remainder == 0:
    units_label = units[-1][2] + 's' if is_long else units[-1][1]
    return '%s%s' % (label_format % count, units_label)

  for count_per_unit, short_label, long_label in units:
    if remainder >= count_per_unit or count_per_unit == 1:
      if not round:
        # Rounding down with a '%f' is a little clunky. Reducing the remainder
        # so it'll divide evenly as the rounded down value.

        remainder -= remainder % (count_per_unit / (10 ** decimal))

      count_label = label_format % (remainder / count_per_unit)

      if is_long:
        # Pluralize if any of the visible units make it greater than one. For
        # instance 1.0003 is plural but 1.000 isn't.

        if decimal > 0:
          is_plural = remainder > count_per_unit
        else:
          is_plural = remainder >= count_per_unit * 2

        return count_label + long_label + ('s' if is_plural else '')
      else:
        return count_label + short_label

  raise ValueError('BUG: %s should always be divisible by a unit (%s)' % (count, str(units)))
