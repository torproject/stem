"""
Connection and networking based utility functions. This will likely be expanded
later to have all of arm's functions...
https://gitweb.torproject.org/arm.git/blob/HEAD:/src/util/connections.py

but for now just moving the parts we need.
"""

def is_valid_ip_address(entry):
  """
  Checks if a string is a valid IPv4 address.
  
  Arguments:
    entry (str) - string to be checked
  
  Returns:
    True if input is a valid IPv4 address, False otherwise.
  """
  
  # checks if theres four period separated values
  if not entry.count(".") == 3: return False
  
  # checks that each value in the octet are decimal values between 0-255
  for entry in entry.split("."):
    if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False # leading zeros, for instance in "1.2.3.001"
  
  return True

def is_valid_port(entry, allow_zero = False):
  """
  Checks if a string or int is a valid port number.
  
  Arguments:
    entry (str or int) - string or integer to be checked
    allow_zero (bool)  - accept port number of zero (reserved by defintion)
  
  Returns:
    True if input is an integer and within the valid port range, False
    otherwise.
  """
  
  if isinstance(entry, str):
    if not entry.isdigit():
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False # leading zeros, ex "001"
    
    entry = int(entry)
  
  if allow_zero and entry == 0: return True
  
  return entry > 0 and entry < 65536

