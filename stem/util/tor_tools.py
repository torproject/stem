"""
Miscellaneous utility functions for working with tor.
"""

import re

# The control-spec defines the following as...
#   Fingerprint = "$" 40*HEXDIG
#   NicknameChar = "a"-"z" / "A"-"Z" / "0" - "9"
#   Nickname = 1*19 NicknameChar
#
# HEXDIG is defined in RFC 5234 as being uppercase and used in RFC 5987 as
# case insensitive. Tor doesn't define this in the spec so flipping a coin
# and going with case insensitive.

HEX_DIGIT = "[0-9a-fA-F]"
FINGERPRINT_PATTERN = re.compile("^%s{40}$" % HEX_DIGIT)
NICKNAME_PATTERN = re.compile("^[a-zA-Z0-9]{1,19}$")

def is_valid_fingerprint(entry, check_prefix = False):
  """
  Checks if a string is a properly formatted relay fingerprint. This checks for
  a '$' prefix if check_prefix is true, otherwise this only validates the hex
  digits.
  
  :param str entry: string to be checked
  :param bool check_prefix: checks for a '$' prefix
  
  :returns: True if the string could be a relay fingerprint, False otherwise.
  """
  
  if check_prefix:
    if not entry or entry[0] != "$": return False
    entry = entry[1:]
  
  return bool(FINGERPRINT_PATTERN.match(entry))

def is_valid_nickname(entry):
  """
  Checks if a string is a valid format for being a nickname.
  
  :param str entry: string to be checked
  
  :returns: True if the string could be a nickname, False otherwise.
  """
  
  return bool(NICKNAME_PATTERN.match(entry))

def is_hex_digits(entry, count):
  """
  Checks if a string is the given number of hex digits. Digits represented by
  letters are case insensitive.
  
  :param str entry: string to be checked
  :param int count: number of hex digits to be checked for
  
  :returns: True if the string matches this number
  """
  
  return bool(re.match("^%s{%i}$" % (HEX_DIGIT, count), entry))

