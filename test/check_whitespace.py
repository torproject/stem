"""
Performs a check that our python source code follows its whitespace conventions
which are...

* two space indentations
* tabs are the root of all evil and should be shot on sight
* no trailing whitespace unless the line is empty, in which case it should have
  the same indentation as the surrounding code
"""

import re
import os

# if ran directly then run over everything one level up
DEFAULT_TARGET = os.path.sep.join(__file__.split(os.path.sep)[:-1])

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
  
  for file_path in _get_python_files(base_path):
    with open(file_path) as f: file_contents = f.read()
    lines, file_issues, prev_indent = file_contents.splitlines(), [], 0
    
    for i in xrange(len(lines)):
      whitespace, content = re.match("^(\s*)(.*)$", lines[i]).groups()
      
      if "\t" in whitespace:
        file_issues.append((i + 1, "indentation has a tab"))
      elif content != content.rstrip():
        file_issues.append((i + 1, "line has trailing whitespace"))
      elif content == '':
        # empty line, check its indentation against the previous and next line
        # with content
        
        next_indent = 0
        
        for k in xrange(i + 1, len(lines)):
          future_whitespace, future_content = re.match("^(\s*)(.*)$", lines[k]).groups()
          
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
          
          file_issues.append((i + 1, msg))
      else:
        # we had content and it's fine, making a note of its indentation
        prev_indent = len(whitespace)
    
    if file_issues:
      issues[file_path] = file_issues
  
  return issues

def _get_python_files(base_path):
  """
  Iterates over all of the python files within a directory.
  
  :param str base_path: directory to be iterated over
  
  :returns: iterator that yields the absolute path for python source code
  """
  
  for root, _, files in os.walk(base_path, followlinks = True):
    for filename in files:
      if filename.endswith(".py"):
        yield os.path.join(root, filename)

if __name__ == '__main__':
  issues = get_issues()
  
  for file_path in issues:
    print file_path
    
    for line_number, msg in issues[file_path]:
      line_count = "%-4s" % line_number
      print "  line %s %s" % (line_count, msg)
    
    print

