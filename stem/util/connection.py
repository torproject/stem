"""
Connection and networking based utility functions. This will likely be expanded
later to have all of arm's functions...
https://gitweb.torproject.org/arm.git/blob/HEAD:/src/util/connections.py

but for now just moving the parts we need.
"""

def is_valid_ip_address(address):
  """
  Checks if a string is a valid IPv4 address.
  
  Arguments:
    address (str) - string to be checked
  
  Returns:
    True if input is a valid IPv4 address, false otherwise.
  """
  
  # checks if theres four period separated values
  if not address.count(".") == 3: return False
  
  # checks that each value in the octet are decimal values between 0-255
  for entry in address.split("."):
    if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False # leading zeros, for instance in "1.2.3.001"
  
  return True

