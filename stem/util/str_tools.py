"""
Toolkit for various string activity.

**Module Overview:**

::

  to_camel_case - converts a string to camel case
  get_size_label - human readable label for a number of bytes
  get_time_label - human readable label for a number of seconds
  get_time_labels - human readable labels for each time unit
  get_short_time_label - condensed time label output
  parse_short_time_label - seconds represented by a short time label
  
  parse_iso_timestamp - parses an ISO timestamp as a datetime value
"""

import datetime

# label conversion tuples of the form...
# (bits / bytes / seconds, short label, long label)
SIZE_UNITS_BITS = (
  (140737488355328.0, " Pb", " Petabit"),
  (137438953472.0, " Tb", " Terabit"),
  (134217728.0, " Gb", " Gigabit"),
  (131072.0, " Mb", " Megabit"),
  (128.0, " Kb", " Kilobit"),
  (0.125, " b", " Bit"),
)

SIZE_UNITS_BYTES = (
  (1125899906842624.0, " PB", " Petabyte"),
  (1099511627776.0, " TB", " Terabyte"),
  (1073741824.0, " GB", " Gigabyte"),
  (1048576.0, " MB", " Megabyte"),
  (1024.0, " KB", " Kilobyte"),
  (1.0, " B", " Byte"),
)

TIME_UNITS = (
  (86400.0, "d", " day"),
  (3600.0, "h", " hour"),
  (60.0, "m", " minute"),
  (1.0, "s", " second"),
)

def to_camel_case(label, word_divider = " "):
  """
  Converts the given string to camel case, ie:
  
  ::
  
    >>> to_camel_case("I_LIKE_PEPPERJACK!")
    'I Like Pepperjack!'
  
  :param str label: input string to be converted
  :param str word_divider: string used to replace underscores
  
  :returns: camel cased string
  """
  
  words = []
  for entry in label.split("_"):
    if len(entry) == 0: words.append("")
    elif len(entry) == 1: words.append(entry.upper())
    else: words.append(entry[0].upper() + entry[1:].lower())
  
  return word_divider.join(words)

def get_size_label(byte_count, decimal = 0, is_long = False, is_bytes = True):
  """
  Converts a number of bytes into a human readable label in its most
  significant units. For instance, 7500 bytes would return "7 KB". If the
  is_long option is used this expands unit labels to be the properly pluralized
  full word (for instance 'Kilobytes' rather than 'KB'). Units go up through
  petabytes.
  
  ::
  
    >>> get_size_label(2000000)
    '1 MB'
    
    >>> get_size_label(1050, 2)
    '1.02 KB'
    
    >>> get_size_label(1050, 3, True)
    '1.025 Kilobytes'
  
  :param int byte_count: number of bytes to be converted
  :param int decimal: number of decimal digits to be included
  :param bool is_long: expands units label
  :param bool is_bytes: provides units in bytes if **True**, bits otherwise
  
  :returns: **str** with human readable representation of the size
  """
  
  if is_bytes: return _get_label(SIZE_UNITS_BYTES, byte_count, decimal, is_long)
  else: return _get_label(SIZE_UNITS_BITS, byte_count, decimal, is_long)

def get_time_label(seconds, decimal = 0, is_long = False):
  """
  Converts seconds into a time label truncated to its most significant units.
  For instance, 7500 seconds would return "2h". Units go up through days.
  
  This defaults to presenting single character labels, but if the is_long
  option is used this expands labels to be the full word (space included and
  properly pluralized). For instance, "4h" would be "4 hours" and "1m" would
  become "1 minute".
  
  ::
  
    >>> get_time_label(10000)
    '2h'
    
    >>> get_time_label(61, 1, True)
    '1.0 minute'
    
    >>> get_time_label(61, 2, True)
    '1.01 minutes'
  
  :param int seconds: number of seconds to be converted
  :param int decimal: number of decimal digits to be included
  :param bool is_long: expands units label
  
  :returns: **str** with human readable representation of the time
  """
  
  return _get_label(TIME_UNITS, seconds, decimal, is_long)

def get_time_labels(seconds, is_long = False):
  """
  Provides a list of label conversions for each time unit, starting with its
  most significant units on down. Any counts that evaluate to zero are omitted.
  For example...
  
  ::
  
    >>> get_time_labels(400)
    ['6m', '40s']
    
    >>> get_time_labels(3640, True)
    ['1 hour', '40 seconds']
  
  :param int seconds: number of seconds to be converted
  :param bool is_long: expands units label
  
  :returns: **list** of strings with human readable representations of the time
  """
  
  time_labels = []
  
  for count_per_unit, _, _ in TIME_UNITS:
    if abs(seconds) >= count_per_unit:
      time_labels.append(_get_label(TIME_UNITS, seconds, 0, is_long))
      seconds %= count_per_unit
  
  return time_labels

def get_short_time_label(seconds):
  """
  Provides a time in the following format:
  [[dd-]hh:]mm:ss
  
  ::
  
    >>> get_short_time_label(111)
    '01:51'
    
    >>> get_short_time_label(544100)
    '6-07:08:20'
    
  :param int seconds: number of seconds to be converted
  
  :returns: **str** with the short representation for the time
  
  :raises: **ValueError** if the input is negative
  """
  
  if seconds < 0:
    raise ValueError("Input needs to be a non-negative integer, got '%i'" % seconds)
  
  time_comp = {}
  
  for amount, _, label in TIME_UNITS:
    count = int(seconds / amount)
    seconds %= amount
    time_comp[label.strip()] = count
  
  label = "%02i:%02i" % (time_comp["minute"], time_comp["second"])
  
  if time_comp["day"]:
    label = "%i-%02i:%s" % (time_comp["day"], time_comp["hour"], label)
  elif time_comp["hour"]:
    label = "%02i:%s" % (time_comp["hour"], label)
  
  return label

def parse_short_time_label(label):
  """
  Provides the number of seconds corresponding to the formatting used for the
  cputime and etime fields of ps:
  [[dd-]hh:]mm:ss or mm:ss.ss
  
  ::
  
    >>> parse_short_time_label('01:51')
    111
    
    >>> parse_short_time_label('6-07:08:20')
    544100
    
  :param str label: time entry to be parsed
  
  :returns: **int** with the number of seconds represented by the label
  
  :raises: **ValueError** if input is malformed
  """
  
  days, hours, minutes, seconds = '0', '0', '0', '0'
  
  if '-' in label:
    days, label = label.split('-', 1)
  
  time_comp = label.split(":")
  
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
    raise ValueError("Non-numeric value in time entry: %s" % label)

def parse_iso_timestamp(entry):
  """
  Parses the ISO 8601 standard that provides for timestamps like...
  
  ::
  
    2012-11-08T16:48:41.420251
  
  :param str entry: timestamp to be parsed
  
  :returns: datetime for the time represented by the timestamp
  
  :raises: ValueError if the timestamp is malformed
  """
  
  if not isinstance(entry, str):
    raise ValueError("parse_iso_timestamp() input must be a str, got a %s" % type(entry))
  
  # based after suggestions from...
  # http://stackoverflow.com/questions/127803/how-to-parse-iso-formatted-date-in-python
  
  if '.' in entry:
    timestamp_str, microseconds = entry.split('.')
  else:
    timestamp_str, microseconds = entry, '000000'
  
  if len(microseconds) != 6 or not microseconds.isdigit():
    raise ValueError("timestamp's microseconds should be six digits")
  
  timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
  return timestamp + datetime.timedelta(microseconds = int(microseconds))

def _get_label(units, count, decimal, is_long):
  """
  Provides label corresponding to units of the highest significance in the
  provided set. This rounds down (ie, integer truncation after visible units).
  
  :param tuple units: type of units to be used for conversion, containing
    (count_per_unit, short_label, long_label)
  :param int count: number of base units being converted
  :param int decimal: decimal precision of label
  :param bool is_long: uses the long label if **True&&, short label otherwise
  """
  
  # formatted string for the requested number of digits
  label_format = "%%.%if" % decimal
  
  # for zero or negative values use the smallest units
  if count < 1:
    units_label = units[-1][2] + "s" if is_long else units[-1][1]
    return "%s%s" % (label_format % count, units_label)
  
  for count_per_unit, short_label, long_label in units:
    if count >= count_per_unit:
      # Rounding down with a '%f' is a little clunky. Reducing the count so
      # it'll divide evenly as the rounded down value.
      
      count -= count % (count_per_unit / (10 ** decimal))
      count_label = label_format % (count / count_per_unit)
      
      if is_long:
        # Pluralize if any of the visible units make it greater than one. For
        # instance 1.0003 is plural but 1.000 isn't.
        
        if decimal > 0:
          is_plural = count > count_per_unit
        else:
          is_plural = count >= count_per_unit * 2
        
        return count_label + long_label + ("s" if is_plural else "")
      else:
        return count_label + short_label

