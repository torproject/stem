"""
Variety of filters for the python unit testing output, which can be chained
together for improved readability.
"""

import re

import stem.util.enum
import stem.util.term as term

LineType = stem.util.enum.Enum("OK", "FAIL", "ERROR", "SKIPPED", "CONTENT")

LINE_ENDINGS = {
  "... ok": LineType.OK,
  "... FAIL": LineType.FAIL,
  "... ERROR": LineType.ERROR,
  "... skipped": LineType.SKIPPED,
}

LINE_ATTR = {
  LineType.OK: (term.Color.GREEN,),
  LineType.FAIL: (term.Color.RED, term.Attr.BOLD),
  LineType.ERROR: (term.Color.RED, term.Attr.BOLD),
  LineType.SKIPPED: (term.Color.BLUE,),
  LineType.CONTENT: (term.Color.CYAN,),
}

def apply_filters(testing_output, *filters):
  """
  Gets the tests results, possably processed through a series of filters. The
  filters are applied in order, each getting the output of the previous.
  
  A filter's input arguments should be the line's (type, content) and the
  output is either a string with the new content or None if the line should be
  omitted.
  
  Arguments:
    testing_output (str) - output from the unit testing
    filters (list) - functors to be applied to each line of the results
  
  Returns:
    str with the processed test results
  """
  
  results = []
  
  for line in testing_output.split("\n"):
    # determine the type of the line
    line_type = LineType.CONTENT
    
    for ending in LINE_ENDINGS:
      if line.endswith(ending):
        line_type = LINE_ENDINGS[ending]
        break
    
    for result_filter in filters:
      line = result_filter(line_type, line)
      if line == None: break
    
    if line != None:
      results.append(line)
  
  return "\n".join(results)

def colorize(line_type, line_content):
  """
  Applies escape sequences so each line is colored according to its type.
  """
  
  return term.format(line_content, *LINE_ATTR[line_type])

def strip_module(line_type, line_content):
  """
  Removes the module name from testing output. This information tends to be
  repetative, and redundant with the headers.
  """
  
  m = re.match(".*( \(.*?\)).*", line_content)
  if m: line_content = line_content.replace(m.groups()[0], "", 1)
  return line_content

class ErrorTracker:
  """
  Stores any failure or error results we've encountered.
  """
  
  def __init__(self):
    self._errors = []
  
  def has_error_occured(self):
    return bool(self._errors)
  
  def get_filter(self):
    def _error_tracker(line_type, line_content):
      if line_type in (LineType.FAIL, LineType.ERROR):
        self._errors.append(line_content)
      
      return line_content
    
    return _error_tracker
  
  def __iter__(self):
    for error_line in self._errors:
      yield error_line

