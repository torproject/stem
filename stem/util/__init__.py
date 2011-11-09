"""
Utility functions used by the stem library.
"""

# Adds a default nullhandler for the stem logger, suppressing the 'No handlers
# could be found for logger "stem"' warning as per...
# http://docs.python.org/release/3.1.3/library/logging.html#configuring-logging-for-a-library

import logging

class NullHandler(logging.Handler):
  def emit(self, record): pass

logging.getLogger("stem").addHandler(NullHandler())

__all__ = ["conf", "enum", "log", "proc", "system", "term"]

