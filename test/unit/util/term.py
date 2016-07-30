"""
Unit tests for the stem.util.term functions.
"""

import unittest

import stem.util.term

from stem.util.term import Color, Attr


class TestTerminal(unittest.TestCase):
  def test_encoding(self):
    """
    Exercises our encoding function.
    """

    self.assertEqual(None, stem.util.term.encoding())
    self.assertEqual('\x1b[31m', stem.util.term.encoding(Color.RED))
    self.assertEqual('\x1b[31;1m', stem.util.term.encoding(Color.RED, Attr.BOLD))

  def test_format(self):
    """
    Exercises our format function.
    """

    self.assertEqual('hi!', stem.util.term.format('hi!'))
    self.assertEqual('\x1b[31mhi!\x1b[0m', stem.util.term.format('hi!', Color.RED))
    self.assertEqual('\x1b[31;1mhi!\x1b[0m', stem.util.term.format('hi!', Color.RED, Attr.BOLD))
    self.assertEqual('\x1b[31mhi\nthere!\x1b[0m', stem.util.term.format('hi\nthere!', Color.RED))
    self.assertEqual('\x1b[31mhi\x1b[0m\n\x1b[31mthere!\x1b[0m', stem.util.term.format('hi\nthere!', Color.RED, Attr.LINES))
    self.assertEqual('\001\x1b[31m\002hi!\001\x1b[0m\002', stem.util.term.format('hi!', Color.RED, Attr.READLINE_ESCAPE))
