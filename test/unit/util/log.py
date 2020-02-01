"""
Unit tests for the stem.util.log functions.
"""

import logging
import unittest

from stem.util import log


class TestLog(unittest.TestCase):
  def test_is_tracing(self):
    logger = log.get_logger()
    original_handlers = logger.handlers
    logger.handlers = [log._NullHandler()]

    try:
      self.assertFalse(log.is_tracing())

      handler = logging.NullHandler()
      handler.setLevel(log.DEBUG)
      logger.addHandler(handler)

      self.assertFalse(log.is_tracing())

      handler = logging.NullHandler()
      handler.setLevel(log.TRACE)
      logger.addHandler(handler)

      self.assertTrue(log.is_tracing())
    finally:
      logger.handlers = original_handlers
