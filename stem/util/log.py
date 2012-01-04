"""
Functions to aid library logging. Default logging is usually NOTICE and above,
runlevels being used as follows...

  ERROR  - critical issue occured, the user needs to be notified
  WARN   - non-critical issue occured that the user should be aware of
  NOTICE - information that is helpful to the user
  INFO   - high level library activity
  DEBUG  - low level library activity
  TRACE  - request/reply logging
"""

import logging

import stem.util.enum

# Logging runlevels. These are *very* commonly used so including shorter
# aliases (so they can be referenced as log.DEBUG, log.WARN, etc).

Runlevel = stem.util.enum.Enum(
  ("TRACE", "TRACE"),   ("DEBUG", "DEBUG"), ("INFO", "INFO"),
  ("NOTICE", "NOTICE"), ("WARN", "WARN"),   ("ERROR", "ERROR"))

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

LOGGER = logging.getLogger("stem")
LOGGER.setLevel(LOG_VALUES[TRACE])

# There's some messages that we don't want to log more than once. This set has
# the messages IDs that we've logged which fall into this category.
DEDUPLICATION_MESSAGE_IDS = set()

# Adds a default nullhandler for the stem logger, suppressing the 'No handlers
# could be found for logger "stem"' warning as per...
# http://docs.python.org/release/3.1.3/library/logging.html#configuring-logging-for-a-library

class NullHandler(logging.Handler):
  def emit(self, record): pass

if not LOGGER.handlers:
  LOGGER.addHandler(NullHandler())

def get_logger():
  """
  Provides the stem logger.
  
  Returns:
    logging.Logger for stem
  """
  
  return LOGGER

def logging_level(runlevel):
  """
  Translates a runlevel into the value expected by the logging module.
  
  Arguments:
    runlevel (Runlevel) - runlevel to be returned, no logging if None
  """
  
  if runlevel: return LOG_VALUES[runlevel]
  else: return logging.FATAL + 5

def log(runlevel, message):
  """
  Logs a message at the given runlevel.
  
  Arguments:
    runlevel (Runlevel) - runlevel to log the message at, logging is skipped if
                          None
    message (str)       - message to be logged
  """
  
  if runlevel:
    LOGGER.log(LOG_VALUES[runlevel], message)

def log_once(message_id, runlevel, message):
  """
  Logs a message at the given runlevel. If a message with this ID has already
  been logged then this is a no-op.
  
  Arguments:
    message_id (str)    - unique message identifier to deduplicate on
    runlevel (Runlevel) - runlevel to log the message at, logging is skipped if
                          None
    message (str)       - message to be logged
  
  Returns:
    True if we log the message, False otherwise
  """
  
  if not runlevel or message_id in DEDUPLICATION_MESSAGE_IDS:
    return False
  else:
    DEDUPLICATION_MESSAGE_IDS.add(message_id)
    log(runlevel, message)

# shorter aliases for logging at a runlevel
def trace(message):  log(Runlevel.TRACE, message)
def debug(message):  log(Runlevel.DEBUG, message)
def info(message):   log(Runlevel.INFO, message)
def notice(message): log(Runlevel.NOTICE, message)
def warn(message):   log(Runlevel.WARN, message)
def error(message):  log(Runlevel.ERROR, message)

def escape(message):
  """
  Escapes specific sequences for logging (newlines, tabs, carrage returns).
  
  Arguments:
    message (str) - string to be escaped
  
  Returns:
    str that is escaped
  """
  
  for pattern, replacement in (("\n", "\\n"), ("\r", "\\r"), ("\t", "\\t")):
    message = message.replace(pattern, replacement)
  
  return message


