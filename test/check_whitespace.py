"""
Performs a check that our python source code follows its whitespace conventions
which are...

* two space indentations
* tabs are the root of all evil and should be shot on sight
* standard newlines (\\n), not windows (\\r\\n) nor classic mac (\\r)
* no trailing whitespace unless the line is empty, in which case it should have
  the same indentation as the surrounding code

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
  
  # pep8 give output of the form...
  #
  #   FILE:LINE:CHARACTER ISSUE
  #
  # ... for instance...
  #
  #   ./test/mocking.py:868:31: E225 missing whitespace around operator
  
  # TODO: Presently this is a list of all issues pep8 complains about in stem.
  # We're gonna trim these down by cateogry but include the pep8 checks to
  # prevent regression.
  
  ignored_issues = "E111,E121,W293,E501,E302,E701,E251,E261,W391,E127,E241,E128,E226,E231,E202,E201,E203,E124,E211,E222,E225,E221,E126,E262,E271,E502"
  
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
    with open(file_path) as f: file_contents = f.read()
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
        
        if not len(whitespace) in (prev_indent, next_indent):
          msg = "indentation should match surrounding content (%s spaces)"
          
          if prev_indent == next_indent:
            msg = msg % prev_indent
          elif prev_indent < next_indent:
            msg = msg % ("%i or %i" % (prev_indent, next_indent))
          else:
            msg = msg % ("%i or %i" % (next_indent, prev_indent))
          
          file_issues.append((index + 1, msg))
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

