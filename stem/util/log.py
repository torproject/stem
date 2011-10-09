"""
Tracks application events, both directing them to attached listeners and
keeping a record of them. A limited space is provided for old events, keeping
and trimming them on a per-runlevel basis (ie, too many DEBUG events will only
result in entries from that runlevel being dropped). All functions are thread
safe.
"""

import time
from sys import maxint
from threading import RLock

from stem.util import enum

# Logging runlevels. These are *very* commonly used so including shorter
# aliases (so they can be referenced as log.DEBUG, log.WARN, etc).
Runlevel = enum.Enum(*[(v, v) for v in ("DEBUG", "INFO", "NOTICE", "WARN", "ERR")])
DEBUG, INFO, NOTICE, WARN, ERR = Runlevel.values()

LOG_LOCK = RLock()        # provides thread safety for logging operations
MAX_LOG_SIZE = 1000       # maximum log entries per runlevel to be persisted

# chronologically ordered records of events for each runlevel, stored as tuples
# consisting of: (time, message)
_backlog = dict([(level, []) for level in Runlevel.values()])

# mapping of runlevels to the listeners interested in receiving events from it
_listeners = dict([(level, []) for level in Runlevel.values()])

def log(level, msg, event_time = None):
  """
  Registers an event, directing it to interested listeners and preserving it in
  the backlog.
  
  Arguments:
    level (Runlevel) - runlevel corresponding to the message severity
    msg (str)        - string associated with the message
    event_time (int) - unix time at which the event occurred, current time if
                       undefined
  """
  
  if event_time == None: event_time = time.time()
  
  LOG_LOCK.acquire()
  try:
    new_event = (event_time, msg)
    event_backlog = _backlog[level]
    
    # inserts the new event into the backlog
    if not event_backlog or event_time >= event_backlog[-1][0]:
      # newest event - append to end
      event_backlog.append(new_event)
    elif event_time <= event_backlog[0][0]:
      # oldest event - insert at start
      event_backlog.insert(0, new_event)
    else:
      # somewhere in the middle - start checking from the end
      for i in range(len(event_backlog) - 1, -1, -1):
        if event_backlog[i][0] <= event_time:
          event_backlog.insert(i + 1, new_event)
          break
    
    # truncates backlog if too long
    to_delete = len(event_backlog) - MAX_LOG_SIZE
    if to_delete > 0: del event_backlog[:to_delete]
    
    # notifies listeners
    for callback in _listeners[level]:
      callback(level, msg, event_time)
  finally:
    LOG_LOCK.release()

def add_listener(levels, callback, dump_backlog = False):
  """
  Directs future events to the given callback function.
  
  Arguments:
    levels (list)       - runlevels for the listener to be notified of
    callback (functor)  - functor to accept the events, of the form:
                          my_function(runlevel, msg, time)
    dump_backlog (bool) - if true then this passes prior events to the callback
                          function (in chronological order) before returning
  """
  
  LOG_LOCK.acquire()
  try:
    for level in levels:
      if not callback in _listeners[level]:
        _listeners[level].append(callback)
    
    if dump_backlog:
      for level, msg, event_time in _get_entries(levels):
        callback(level, msg, event_time)
  finally:
    LOG_LOCK.release()

def remove_listener(level, callback):
  """
  Prevents a listener from being notified of further events.
  
  Arguments:
    level (Runlevel)   - runlevel for the listener to be removed from
    callback (functor) - functor to be removed
  
  Returns:
    True if a listener was removed, False otherwise
  """
  
  if callback in _listeners[level]:
    _listeners[level].remove(callback)
    return True
  else: return False

def _get_entries(levels):
  """
  Generator for providing past events belonging to the given runlevels (in
  chronological order). This should be used under the LOG_LOCK to prevent
  concurrent modifications.
  
  Arguments:
    levels (list) - runlevels for which events are provided
  """
  
  # drops any runlevels if there aren't entries in it
  to_remove = [level for level in levels if not _backlog[level]]
  for level in to_remove: levels.remove(level)
  
  # tracks where unprocessed entries start in the backlog
  backlog_ptr = dict([(level, 0) for level in levels])
  
  while levels:
    earliest_level, earliest_msg, earliest_time = None, "", maxint
    
    # finds the earliest unprocessed event
    for level in levels:
      entry = _backlog[level][backlog_ptr[level]]
      
      if entry[0] < earliest_time:
        earliest_level, earliest_msg, earliest_time = level, entry[1], entry[0]
    
    yield (earliest_level, earliest_msg, earliest_time)
    
    # removes runlevel if there aren't any more entries
    backlog_ptr[earliest_level] += 1
    if len(_backlog[earliest_level]) <= backlog_ptr[earliest_level]:
      levels.remove(earliest_level)

