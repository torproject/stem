"""
Performs a check that our python source code follows its whitespace conventions
which are...

* two space indentations
* tabs are the root of all evil and should be shot on sight
* standard newlines (\\n), not windows (\\r\\n) nor classic mac (\\r)

This also checks for 2.5 compatibility issues (yea, they're not whitespace but
it's so much easier to do here...):

* checks that anything using the 'with' keyword has...
  from __future__ import with_statement
"""

from __future__ import with_statement

import re
import os

from stem.util import system

# if ran directly then run over everything one level up
DEFAULT_TARGET = os.path.sep.join(__file__.split(os.path.sep)[:-1])


def pep8_issues(base_path = DEFAULT_TARGET):
  """
  Checks for stylistic issues that are an issue according to the parts of PEP8
  we conform to.

  :param str base_path: directory to be iterated over

  :returns: dict of the form ``path => [(line_number, message)...]``
  """

  # The pep8 command give output of the form...
  #
  #   FILE:LINE:CHARACTER ISSUE
  #
  # ... for instance...
  #
  #   ./test/mocking.py:868:31: E225 missing whitespace around operator
  #
  # Ignoring the following compliance issues.
  #
  # * E251 no spaces around keyword / parameter equals
  #
  #   This one I dislike a great deal. It makes keyword arguments different
  #   from assignments which looks... aweful. I'm not sure what PEP8's author
  #   was on when he wrote this one but it's stupid.
  #
  #   Someone else can change this if they really care.
  #
  # * E501 line is over 79 characters
  #
  #   We're no longer on TTY terminals. Overly constraining line length makes
  #   things far less readable, encouraging bad practices like abbreviated
  #   variable names.
  #
  #   If the code fits on my tiny netbook screen then it's narrow enough.
  #
  # * E111 and E121 four space indentations
  #
  #   Ahhh, indentation. The holy war that'll never die. Sticking with two
  #   space indentations since it leads to shorter lines.
  #
  # * E127 continuation line over-indented for visual indent
  #
  #   Pep8 only works with this one if we have four space indents (its
  #   detection is based on multiples of four).

  ignored_issues = "E111,E121,E501,E251,E127"

  issues = {}
  pep8_output = system.call("pep8 --ignore %s %s" % (ignored_issues, base_path))

  for line in pep8_output:
    line_match = re.match("^(.*):(\d+):(\d+): (.*)$", line)

    if line_match:
      path, line, _, issue = line_match.groups()
      issues.setdefault(path, []).append((int(line), issue))

  return issues


def get_issues(base_path = DEFAULT_TARGET):
  """
  Checks python source code in the given directory for whitespace issues.

  :param str base_path: directory to be iterated over

  :returns: dict of the form ``path => [(line_number, message)...]``
  """

  # TODO: This does not check that block indentations are two spaces because
  # differentiating source from string blocks ("""foo""") is more of a pita
  # than I want to deal with right now.

  issues = {}

  for file_path in _get_files_with_suffix(base_path):
    with open(file_path) as f:
      file_contents = f.read()

    lines, file_issues, prev_indent = file_contents.split("\n"), [], 0
    has_with_import, given_with_warning = False, False
    is_block_comment = False

    for index, line in enumerate(lines):
      whitespace, content = re.match("^(\s*)(.*)$", line).groups()

      if '"""' in content:
        is_block_comment = not is_block_comment

      if content == "from __future__ import with_statement":
        has_with_import = True
      elif content.startswith("with ") and content.endswith(":") \
        and not has_with_import and not given_with_warning and not is_block_comment:
        file_issues.append((index + 1, "missing 'with' import (from __future__ import with_statement)"))
        given_with_warning = True

      if "\t" in whitespace:
        file_issues.append((index + 1, "indentation has a tab"))
      elif "\r" in content:
        file_issues.append((index + 1, "contains a windows newline"))
      elif content != content.rstrip():
        file_issues.append((index + 1, "line has trailing whitespace"))
      elif content == '':
        # empty line, check its indentation against the previous and next line
        # with content

        next_indent = 0

        for future_index in xrange(index + 1, len(lines)):
          future_whitespace, future_content = re.match("^(\s*)(.*)$", lines[future_index]).groups()

          if future_content:
            next_indent = len(future_whitespace)
            break
      else:
        # we had content and it's fine, making a note of its indentation
        prev_indent = len(whitespace)

    if file_issues:
      issues[file_path] = file_issues

  return issues


def _get_files_with_suffix(base_path, suffix = ".py"):
  """
  Iterates over files in a given directory, providing filenames with a certain
  suffix.

  :param str base_path: directory to be iterated over
  :param str suffix: filename suffix to look for

  :returns: iterator that yields the absolute path for files with the given suffix
  """

  if os.path.isfile(base_path):
    if base_path.endswith(suffix):
      yield base_path
  else:
    for root, _, files in os.walk(base_path):
      for filename in files:
        if filename.endswith(suffix):
          yield os.path.join(root, filename)

if __name__ == '__main__':
  issues = get_issues()

  for file_path in issues:
    print file_path

    for line_number, msg in issues[file_path]:
      line_count = "%-4s" % line_number
      print "  line %s %s" % (line_count, msg)

    print
