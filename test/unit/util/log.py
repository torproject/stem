"""
Unit tests for the stem.util.log functions.
"""

import unittest

from stem.util import log


class TestLog(unittest.TestCase):
  def test_is_tracing(self):
    logger = log.get_logger()
    original_handlers = logger.handlers
    logger.handlers = [log._NullHandler()]

    try:
      self.assertFalse(log.is_tracing())
      logger.addHandler(log.LogBuffer(log.DEBUG))
      self.assertFalse(log.is_tracing())
      logger.addHandler(log.LogBuffer(log.TRACE))
      self.assertTrue(log.is_tracing())
    finally:
      logger.handlers = original_handlers
