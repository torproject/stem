"""
Variety of filters for the python unit testing output, which can be chained
together for improved readability.
"""

import re
import sys

import stem.util.conf
import stem.util.enum

from stem.util import term

CONFIG = stem.util.conf.config_dict("test", {
  "argument.no_color": False,
})

DIVIDER = "=" * 70
HEADER_ATTR = (term.Color.CYAN, term.Attr.BOLD)
CATEGORY_ATTR = (term.Color.GREEN, term.Attr.BOLD)

LineType = stem.util.enum.Enum("OK", "FAIL", "ERROR", "SKIPPED", "CONTENT")

LINE_ENDINGS = {
  " ... ok": LineType.OK,
  " ... FAIL": LineType.FAIL,
  " ... ERROR": LineType.ERROR,
  " ... skipped": LineType.SKIPPED,
}

LINE_ATTR = {
  LineType.OK: (term.Color.GREEN,),
  LineType.FAIL: (term.Color.RED, term.Attr.BOLD),
  LineType.ERROR: (term.Color.RED, term.Attr.BOLD),
  LineType.SKIPPED: (term.Color.BLUE,),
  LineType.CONTENT: (term.Color.CYAN,),
}


def print_line(msg, *attr):
  if CONFIG["argument.no_color"]:
    print msg
  else:
    print term.format(msg, *attr)


def print_noline(msg, *attr):
  if CONFIG["argument.no_color"]:
    sys.stdout.write(msg)
  else:
    sys.stdout.write(term.format(msg, *attr))


def print_divider(msg, is_header = False):
  attr = HEADER_ATTR if is_header else CATEGORY_ATTR
  print_line("%s\n%s\n%s\n" % (DIVIDER, msg.center(70), DIVIDER), *attr)


def print_logging(logging_buffer):
  if not logging_buffer.is_empty():
    for entry in logging_buffer:
      print_line(entry.replace("\n", "\n  "), term.Color.MAGENTA)

    print


def print_config(test_config):
  print_divider("TESTING CONFIG", True)
  print_line("Test configuration... ", term.Color.BLUE, term.Attr.BOLD)

  for config_key in test_config.keys():
    key_entry = "  %s => " % config_key

    # if there's multiple values then list them on separate lines
    value_div = ",\n" + (" " * len(key_entry))
    value_entry = value_div.join(test_config.get_value(config_key, multiple = True))

    print_line(key_entry + value_entry, term.Color.BLUE)

  print


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

  return "\n".join(results) + "\n"


def colorize(line_type, line_content):
  """
  Applies escape sequences so each line is colored according to its type.
  """

  if CONFIG["argument.no_color"]:
    return line_content
  else:
    return term.format(line_content, *LINE_ATTR[line_type])


def strip_module(line_type, line_content):
  """
  Removes the module name from testing output. This information tends to be
  repetitive, and redundant with the headers.
  """

  m = re.match(".*( \(.*?\)).*", line_content)

  if m:
    line_content = line_content.replace(m.groups()[0], "", 1)

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
      line_content = line_content.replace(ending, "", 1)
      break

  # skipped tests have extra single quotes around the reason
  if line_type == LineType.SKIPPED:
    line_content = line_content.replace("'(", "(", 1).replace(")'", ")", 1)

  if line_type == LineType.OK:
    new_ending = "SUCCESS"
  elif line_type in (LineType.FAIL, LineType.ERROR):
    new_ending = "FAILURE"
  elif line_type == LineType.SKIPPED:
    new_ending = "SKIPPED"
  else:
    assert False, "Unexpected line type: %s" % line_type
    return line_content

  if CONFIG["argument.no_color"]:
    return "%-61s[%s]" % (line_content, term.format(new_ending))
  else:
    return "%-61s[%s]" % (line_content, term.format(new_ending, term.Attr.BOLD))


class ErrorTracker(object):
  """
  Stores any failure or error results we've encountered.
  """

  def __init__(self):
    self._errors = []
    self._category = None

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

  def has_error_occured(self):
    return bool(self._errors)

  def get_filter(self):
    def _error_tracker(line_type, line_content):
      if line_type in (LineType.FAIL, LineType.ERROR):
        if self._category:
          self._errors.append("[%s] %s" % (self._category, line_content))
        else:
          self._errors.append(line_content)

      return line_content

    return _error_tracker

  def __iter__(self):
    for error_line in self._errors:
      yield error_line
