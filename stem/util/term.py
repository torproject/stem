"""
Utilities for working with the terminal.
"""

import stem.util.enum

TERM_COLORS = ("BLACK", "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE")

Color = stem.util.enum.Enum(*TERM_COLORS)
BgColor = stem.util.enum.Enum(*["BG_" + color for color in TERM_COLORS])
Attr = stem.util.enum.Enum("BOLD", "UNDERLINE", "HILIGHT")

# mappings of terminal attribute enums to their ANSI escape encoding
FG_ENCODING = dict([(Color.values()[i], str(30 + i)) for i in range(8)])
BG_ENCODING = dict([(BgColor.values()[i], str(40 + i)) for i in range(8)])
ATTR_ENCODING = {Attr.BOLD: "1", Attr.UNDERLINE: "4", Attr.HILIGHT: "7"}

CSI = "\x1B[%sm"
RESET = CSI % "0"

def format(msg, *attr):
  """
  Simple terminal text formatting, using ANSI escape sequences from:
  https://secure.wikimedia.org/wikipedia/en/wiki/ANSI_escape_code#CSI_codes
  
  toolkits providing similar capabilities:
  * django.utils.termcolors
    https://code.djangoproject.com/browser/django/trunk/django/utils/termcolors.py
  
  * termcolor
    http://pypi.python.org/pypi/termcolor
  
  * colorama
    http://pypi.python.org/pypi/colorama
  
  Arguments:
    msg (str)  - string to be formatted
    attr (str) - text attributes, this can be Color, BgColor, or Attr enums and
                 are case insensitive (so strings like "red" are fine)
  
  Returns:
    string wrapped with ANSI escape encodings, starting with the given
    attributes and ending with a reset
  """
  
  encodings = []
  for text_attr in attr:
    text_attr, encoding = stem.util.enum.to_camel_case(text_attr), None
    encoding = FG_ENCODING.get(text_attr, encoding)
    encoding = BG_ENCODING.get(text_attr, encoding)
    encoding = ATTR_ENCODING.get(text_attr, encoding)
    if encoding: encodings.append(encoding)
  
  if encodings:
    return (CSI % ";".join(encodings)) + msg + RESET
  else: return msg

