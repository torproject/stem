"""
Utilities for working with the terminal.
"""

import stem.util.enum

TERM_COLORS = ("BLACK", "RED", "GREEN", "YELLOW", "BLUE", "MAGENTA", "CYAN", "WHITE")

Color = stem.util.enum.Enum(*TERM_COLORS)
BgColor = stem.util.enum.Enum(*["BG_" + color for color in TERM_COLORS])
Attr = stem.util.enum.Enum("BOLD", "UNDERLINE", "HILIGHT")

# mappings of terminal attribute enums to their ANSI escape encoding
FG_ENCODING = dict([(list(Color)[i], str(30 + i)) for i in range(8)])
BG_ENCODING = dict([(list(BgColor)[i], str(40 + i)) for i in range(8)])
ATTR_ENCODING = {Attr.BOLD: "1", Attr.UNDERLINE: "4", Attr.HILIGHT: "7"}

CSI = "\x1B[%sm"
RESET = CSI % "0"

def format(msg, *attr):
  """
  Simple terminal text formatting using `ANSI escape sequences
  <https://secure.wikimedia.org/wikipedia/en/wiki/ANSI_escape_code#CSI_codes>`_.
  The following are some toolkits providing similar capabilities:
  
  * `django.utils.termcolors <https://code.djangoproject.com/browser/django/trunk/django/utils/termcolors.py>`_
  * `termcolor <http://pypi.python.org/pypi/termcolor>`_
  * `colorama <http://pypi.python.org/pypi/colorama>`_
  
  :param str msg: string to be formatted
  :param str attr: text attributes, this can be Color, BgColor, or Attr enums and are case insensitive (so strings like "red" are fine)
  
  :returns: string wrapped with ANSI escape encodings, starting with the given attributes and ending with a reset
  """
  
  # if we have reset sequences in the message then apply our attributes
  # after each of them
  if RESET in msg:
    return "".join([format(comp, *attr) for comp in msg.split(RESET)])
  
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

