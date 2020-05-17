# Copyright 2011-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Functions to aid library logging. The default logging
:data:`~stem.util.log.Runlevel` is usually NOTICE and above.

**Stem users are more than welcome to listen for stem events, but these
functions are not being vended to our users. They may change in the future, use
them at your own risk.**

**Module Overview:**

::

  get_logger - provides the stem's Logger instance
  logging_level - converts a runlevel to its logging number
  escape - escapes special characters in a message in preparation for logging

  log - logs a message at the given runlevel
  log_once - logs a message, deduplicating if it has already been logged
  trace - logs a message at the TRACE runlevel
  debug - logs a message at the DEBUG runlevel
  info - logs a message at the INFO runlevel
  notice - logs a message at the NOTICE runlevel
  warn - logs a message at the WARN runlevel
  error - logs a message at the ERROR runlevel

  LogBuffer - Buffers logged events so they can be iterated over.
    |- is_empty - checks if there's events in our buffer
    +- __iter__ - iterates over and removes the buffered events

  log_to_stdout - reports further logged events to stdout

.. data:: Runlevel (enum)

  Enumeration for logging runlevels.

  ========== ===========
  Runlevel   Description
  ========== ===========
  **ERROR**  critical issue occurred, the user needs to be notified
  **WARN**   non-critical issue occurred that the user should be aware of
  **NOTICE** information that is helpful to the user
  **INFO**   high level library activity
  **DEBUG**  low level library activity
  **TRACE**  request/reply logging
  ========== ===========
"""

import logging

import stem.util.enum
import stem.util.str_tools

# Logging runlevels. These are *very* commonly used so including shorter
# aliases (so they can be referenced as log.DEBUG, log.WARN, etc).

Runlevel = stem.util.enum.UppercaseEnum('TRACE', 'DEBUG', 'INFO', 'NOTICE', 'WARN', 'ERROR')
TRACE, DEBUG, INFO, NOTICE, WARN, ERR = list(Runlevel)

# mapping of runlevels to the logger module's values, TRACE and DEBUG aren't
# built into the module

LOG_VALUES = {
  Runlevel.TRACE: logging.DEBUG - 5,
  Runlevel.DEBUG: logging.DEBUG,
  Runlevel.INFO: logging.INFO,
  Runlevel.NOTICE: logging.INFO + 5,
  Runlevel.WARN: logging.WARN,
  Runlevel.ERROR: logging.ERROR,
}

logging.addLevelName(LOG_VALUES[TRACE], 'TRACE')
logging.addLevelName(LOG_VALUES[NOTICE], 'NOTICE')

LOGGER = logging.getLogger('stem')
LOGGER.setLevel(LOG_VALUES[TRACE])

FORMATTER = logging.Formatter(
  fmt = '%(asctime)s [%(levelname)s] %(message)s',
  datefmt = '%m/%d/%Y %H:%M:%S',
)

# There's some messages that we don't want to log more than once. This set has
# the messages IDs that we've logged which fall into this category.
DEDUPLICATION_MESSAGE_IDS = set()

# Adds a default nullhandler for the stem logger, suppressing the 'No handlers
# could be found for logger "stem"' warning as per...
# http://docs.python.org/release/3.1.3/library/logging.html#configuring-logging-for-a-library


class _NullHandler(logging.Handler):
  def __init__(self) -> None:
    logging.Handler.__init__(self, level = logging.FATAL + 5)  # disable logging

  def emit(self, record: logging.LogRecord) -> None:
    pass


if not LOGGER.handlers:
  LOGGER.addHandler(_NullHandler())


def get_logger() -> logging.Logger:
  """
  Provides the stem logger.

  :returns: **logging.Logger** for stem
  """

  return LOGGER


def logging_level(runlevel: 'stem.util.log.Runlevel') -> int:
  """
  Translates a runlevel into the value expected by the logging module.

  :param runlevel: runlevel to be returned, no logging if **None**
  """

  if runlevel:
    return LOG_VALUES[runlevel]
  else:
    return logging.FATAL + 5


def is_tracing() -> bool:
  """
  Checks if we're logging at the trace runlevel.

  .. versionadded:: 1.6.0

  :returns: **True** if we're logging at the trace runlevel and **False** otherwise
  """

  for handler in get_logger().handlers:
    if handler.level <= logging_level(TRACE):
      return True

  return False


def escape(message: str) -> str:
  """
  Escapes specific sequences for logging (newlines, tabs, carriage returns). If
  the input is **bytes** then this converts it to **unicode** under python 3.x.

  :param message: string to be escaped

  :returns: str that is escaped
  """

  message = stem.util.str_tools._to_unicode(message)

  for pattern, replacement in (('\n', '\\n'), ('\r', '\\r'), ('\t', '\\t')):
    message = message.replace(pattern, replacement)

  return message


def log(runlevel: 'stem.util.log.Runlevel', message: str) -> None:
  """
  Logs a message at the given runlevel.

  :param runlevel: runlevel to log the message at, logging is skipped if **None**
  :param message: message to be logged
  """

  if runlevel:
    LOGGER.log(LOG_VALUES[runlevel], message)


def log_once(message_id: str, runlevel: 'stem.util.log.Runlevel', message: str) -> bool:
  """
  Logs a message at the given runlevel. If a message with this ID has already
  been logged then this is a no-op.

  :param message_id: unique message identifier to deduplicate on
  :param runlevel: runlevel to log the message at, logging is skipped if **None**
  :param message: message to be logged

  :returns: **True** if we log the message, **False** otherwise
  """

  if not runlevel or message_id in DEDUPLICATION_MESSAGE_IDS:
    return False
  else:
    DEDUPLICATION_MESSAGE_IDS.add(message_id)
    log(runlevel, message)
    return True

# shorter aliases for logging at a runlevel


def trace(message: str) -> None:
  log(Runlevel.TRACE, message)


def debug(message: str) -> None:
  log(Runlevel.DEBUG, message)


def info(message: str) -> None:
  log(Runlevel.INFO, message)


def notice(message: str) -> None:
  log(Runlevel.NOTICE, message)


def warn(message: str) -> None:
  log(Runlevel.WARN, message)


def error(message: str) -> None:
  log(Runlevel.ERROR, message)


class _StdoutLogger(logging.Handler):
  def __init__(self, runlevel: 'stem.util.log.Runlevel') -> None:
    logging.Handler.__init__(self, level = logging_level(runlevel))

    self.formatter = logging.Formatter(
      fmt = '%(asctime)s [%(levelname)s] %(message)s',
      datefmt = '%m/%d/%Y %H:%M:%S')

  def emit(self, record: logging.LogRecord) -> None:
    print(self.formatter.format(record))


def log_to_stdout(runlevel: 'stem.util.log.Runlevel') -> None:
  """
  Logs further events to stdout.

  :param runlevel: minimum runlevel a message needs to be to be logged
  """

  get_logger().addHandler(_StdoutLogger(runlevel))
