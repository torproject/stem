# Copyright 2011-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Variety of filters for the python unit testing output, which can be chained
together for improved readability.
"""

import re
import sys

import stem.util.enum

from stem.util import system, term

COLOR_SUPPORT = sys.stdout.isatty() and not system.is_windows()

DIVIDER = '=' * 70
HEADER_ATTR = (term.Color.CYAN, term.Attr.BOLD)
CATEGORY_ATTR = (term.Color.GREEN, term.Attr.BOLD)

NO_NL = 'no newline'
STDERR = 'stderr'

# formatting for various categories of messages

STATUS = (term.Color.BLUE, term.Attr.BOLD)
SUBSTATUS = (term.Color.BLUE, )

SUCCESS = (term.Color.GREEN, term.Attr.BOLD)
ERROR = (term.Color.RED, term.Attr.BOLD)

LineType = stem.util.enum.Enum('OK', 'FAIL', 'ERROR', 'SKIPPED', 'CONTENT')

LINE_ENDINGS = {
  ' ... ok': LineType.OK,
  ' ... FAIL': LineType.FAIL,
  ' ... ERROR': LineType.ERROR,
  ' ... skipped': LineType.SKIPPED,
}

LINE_ATTR = {
  LineType.OK: (term.Color.GREEN,),
  LineType.FAIL: (term.Color.RED, term.Attr.BOLD),
  LineType.ERROR: (term.Color.RED, term.Attr.BOLD),
  LineType.SKIPPED: (term.Color.BLUE,),
  LineType.CONTENT: (term.Color.CYAN,),
}

SUPPRESS_STDOUT = False  # prevent anything from being printed to stdout


def println(msg = '', *attr):
  if SUPPRESS_STDOUT and STDERR not in attr:
    return

  attr = _flatten(attr)
  no_newline = False
  stream = sys.stderr if STDERR in attr else sys.stdout

  if NO_NL in attr:
    no_newline = True
    attr.remove(NO_NL)

  if STDERR in attr:
    attr.remove(STDERR)

  if COLOR_SUPPORT and attr:
    msg = term.format(msg, *attr)

  if not no_newline:
    msg += '\n'

  stream.write(msg)
  stream.flush()


def print_divider(msg, is_header = False):
  attr = HEADER_ATTR if is_header else CATEGORY_ATTR
  println('%s\n%s\n%s\n' % (DIVIDER, msg.center(70), DIVIDER), *attr)


def print_logging(logging_buffer):
  if SUPPRESS_STDOUT:
    return

  if not logging_buffer.is_empty():
    for entry in logging_buffer:
      println(entry.replace('\n', '\n  '), term.Color.MAGENTA)

    print()


def apply_filters(testing_output, *filters):
  """
  Gets the tests results, possibly processed through a series of filters. The
  filters are applied in order, each getting the output of the previous.

  A filter's input arguments should be the line's (type, content) and the
  output is either a string with the new content or None if the line should be
  omitted.

  :param str testing_output: output from the unit testing
  :param list filters: functors to be applied to each line of the results

  :returns: str with the processed test results
  """

  results = []

  for line in testing_output.splitlines():
    # determine the type of the line
    line_type = LineType.CONTENT

    for ending in LINE_ENDINGS:
      if ending in line:
        line_type = LINE_ENDINGS[ending]
        break

    for result_filter in filters:
      line = result_filter(line_type, line)

      if line is None:
        break

    if line is not None:
      results.append(line)

  return '\n'.join(results) + '\n'


def colorize(line_type, line_content):
  """
  Applies escape sequences so each line is colored according to its type.
  """

  if COLOR_SUPPORT:
    line_content = term.format(line_content, *LINE_ATTR[line_type])

  return line_content


def strip_module(line_type, line_content):
  """
  Removes the module name from testing output. This information tends to be
  repetitive, and redundant with the headers.
  """

  m = re.match('.*( \(test\..*?\)).*', line_content)

  if m:
    line_content = line_content.replace(m.groups()[0], '', 1)

  return line_content


def align_results(line_type, line_content):
  """
  Strips the normal test results, and adds a right aligned variant instead with
  a bold attribute.
  """

  if line_type == LineType.CONTENT:
    return line_content

  # strip our current ending
  for ending in LINE_ENDINGS:
    if LINE_ENDINGS[ending] == line_type:
      line_content = line_content.replace(ending, '', 1)
      break

  # skipped tests have extra single quotes around the reason
  if line_type == LineType.SKIPPED:
    line_content = line_content.replace("'(", "(", 1).replace(")'", ")", 1)

  if line_type == LineType.OK:
    new_ending = 'SUCCESS'
  elif line_type in (LineType.FAIL, LineType.ERROR):
    new_ending = 'FAILURE'
  elif line_type == LineType.SKIPPED:
    new_ending = 'SKIPPED'
  else:
    assert False, 'Unexpected line type: %s' % line_type
    return line_content

  if COLOR_SUPPORT:
    return '%-61s[%s]' % (line_content, term.format(new_ending, term.Attr.BOLD))
  else:
    return '%-61s[%s]' % (line_content, term.format(new_ending))


class ErrorTracker(object):
  """
  Stores any failure or error results we've encountered.
  """

  def __init__(self):
    self._errors = []
    self._error_modules = set()
    self._category = None
    self._error_noted = False

  def register_error(self):
    """
    If called then has_errors_occured() will report that an error has occured,
    even if we haven't encountered an error message in the tests.
    """

    self._error_noted = True

  def set_category(self, category):
    """
    Optional label that will be presented with testing failures until another
    category is specified. If set to None then no category labels are included.

    For tests with a lot of output this is intended to help narrow the haystack
    in which the user needs to look for failures. In practice this is mostly
    used to specify the integ target we're running under.

    :param str category: category to label errors as being under
    """

    self._category = category

  def has_errors_occured(self):
    return self._error_noted or bool(self._errors)

  def get_filter(self):
    def _error_tracker(line_type, line_content):
      if line_type in (LineType.FAIL, LineType.ERROR):
        if self._category:
          self._errors.append('[%s] %s' % (self._category, line_content))
        else:
          self._errors.append(line_content)

        module_match = re.match('.*\((test\.\S+)\.\S+\).*', line_content)

        if module_match:
          self._error_modules.add(module_match.group(1))

      return line_content

    return _error_tracker

  def get_modules(self):
    return self._error_modules

  def __iter__(self):
    for error_line in self._errors:
      yield error_line


def _flatten(seq):
  # Flattens nested collections into a single list. For instance...
  #
  # >>> _flatten([1, [2, 3], 4])
  # [1, 2, 3, 4]

  result = []

  for item in seq:
    if (isinstance(item, (tuple, list))):
      result.extend(_flatten(item))
    else:
      result.append(item)

  return result
