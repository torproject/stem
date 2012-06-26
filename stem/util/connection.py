"""
Connection and networking based utility functions. This will likely be expanded
later to have all of `arm's functions
<https://gitweb.torproject.org/arm.git/blob/HEAD:/src/util/connections.py>`_,
but for now just moving the parts we need.
"""

import os
import re
import hmac
import hashlib

CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE = os.urandom(32)

def is_valid_ip_address(address):
  """
  Checks if a string is a valid IPv4 address.
  
  :param str address: string to be checked
  
  :returns: True if input is a valid IPv4 address, False otherwise
  """
  
  # checks if theres four period separated values
  if address.count(".") != 3: return False
  
  # checks that each value in the octet are decimal values between 0-255
  for entry in address.split("."):
    if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False # leading zeros, for instance in "1.2.3.001"
  
  return True

def is_valid_ipv6_address(address):
  """
  Checks if a string is a valid IPv6 address.
  
  :param str address: string to be checked
  
  :returns: True if input is a valid IPv6 address, False otherwise
  """
  
  # addresses are made up of eight colon separated groups of four hex digits
  # with leading zeros being optional
  # https://en.wikipedia.org/wiki/IPv6#Address_format
  
  colon_count = address.count(":")
  
  if colon_count > 7:
    return False # too many groups
  elif colon_count != 7 and not "::" in address:
    return False # not enough groups and none are collapsed
  elif address.count("::") > 1 or ":::" in address:
    return False # multiple groupings of zeros can't be collapsed
  
  for entry in address.split(":"):
    if not re.match("^[0-9a-fA-f]{0,4}$", entry):
      return False
  
  return True

def is_valid_port(entry, allow_zero = False):
  """
  Checks if a string or int is a valid port number.
  
  :param list, str, int entry: string, integer or list to be checked
  :param bool allow_zero: accept port number of zero (reserved by defintion)
  
  :returns: True if input is an integer and within the valid port range, False otherwise
  """
  
  if isinstance(entry, list):
    for port in entry:
      if not is_valid_port(port):
        return False

  elif isinstance(entry, str):
    if not entry.isdigit():
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False # leading zeros, ex "001"
    
    entry = int(entry)
  
  if allow_zero and entry == 0: return True
  
  return entry > 0 and entry < 65536

def hmac_sha256(key, msg):
  """
  Generates a sha256 digest using the given key and message.
  
  :param str key: starting key for the hash
  :param str msg: message to be hashed
  
  :returns; A sha256 digest of msg, hashed using the given key.
  """
  
  return hmac.new(key, msg, hashlib.sha256).digest()

def cryptovariables_equal(x, y):
  """
  Compares two strings for equality securely.
  
  :param str x: string to be compared.
  :param str y: the other string to be compared.
  
  :returns: True if both strings are equal, False otherwise.
  """
  
  return (hmac_sha256(CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE, x) ==
      hmac_sha256(CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE, y))

