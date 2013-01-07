"""
Connection and networking based utility functions. This will likely be expanded
later to have all of `arm's functions
<https://gitweb.torproject.org/arm.git/blob/HEAD:/src/util/connections.py>`_,
but for now just moving the parts we need.

::

  is_valid_ip_address - checks if a string is a valid IPv4 address
  is_valid_ipv6_address - checks if a string is a valid IPv6 address
  is_valid_port - checks if something is a valid representation for a port
  expand_ipv6_address - provides an IPv6 address with its collapsed portions expanded
  get_mask - provides the mask representation for a given number of bits
  get_masked_bits - provides the number of bits represented by a mask
  get_mask_ipv6 - provides the IPv6 mask representation for a given number of bits
  get_binary - provides the binary representation for an integer with padding
  get_address_binary - provides the binary representation for an address
  
  hmac_sha256 - provides a sha256 digest
  cryptovariables_equal - string comparison for cryptographic operations
"""

import hashlib
import hmac
import os
import re

CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE = os.urandom(32)

FULL_IPv4_MASK = "255.255.255.255"
FULL_IPv6_MASK = "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF"

def is_valid_ip_address(address):
  """
  Checks if a string is a valid IPv4 address.
  
  :param str address: string to be checked
  
  :returns: **True** if input is a valid IPv4 address, **False** otherwise
  """
  
  if not isinstance(address, str): return False
  
  # checks if theres four period separated values
  if address.count(".") != 3: return False
  
  # checks that each value in the octet are decimal values between 0-255
  for entry in address.split("."):
    if not entry.isdigit() or int(entry) < 0 or int(entry) > 255:
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False  # leading zeros, for instance in "1.2.3.001"
  
  return True

def is_valid_ipv6_address(address, allow_brackets = False):
  """
  Checks if a string is a valid IPv6 address.
  
  :param str address: string to be checked
  :param bool allow_brackets: ignore brackets which form '[address]'
  
  :returns: **True** if input is a valid IPv6 address, **False** otherwise
  """
  
  if allow_brackets:
    if address.startswith("[") and address.endswith("]"):
      address = address[1:-1]
  
  # addresses are made up of eight colon separated groups of four hex digits
  # with leading zeros being optional
  # https://en.wikipedia.org/wiki/IPv6#Address_format
  
  colon_count = address.count(":")
  
  if colon_count > 7:
    return False  # too many groups
  elif colon_count != 7 and not "::" in address:
    return False  # not enough groups and none are collapsed
  elif address.count("::") > 1 or ":::" in address:
    return False  # multiple groupings of zeros can't be collapsed
  
  for entry in address.split(":"):
    if not re.match("^[0-9a-fA-f]{0,4}$", entry):
      return False
  
  return True

def is_valid_port(entry, allow_zero = False):
  """
  Checks if a string or int is a valid port number.
  
  :param list,str,int entry: string, integer or list to be checked
  :param bool allow_zero: accept port number of zero (reserved by definition)
  
  :returns: **True** if input is an integer and within the valid port range, **False** otherwise
  """
  
  if isinstance(entry, list):
    for port in entry:
      if not is_valid_port(port, allow_zero):
        return False
    
    return True
  elif isinstance(entry, str):
    if not entry.isdigit():
      return False
    elif entry[0] == "0" and len(entry) > 1:
      return False  # leading zeros, ex "001"
    
    entry = int(entry)
  
  if allow_zero and entry == 0: return True
  
  return entry > 0 and entry < 65536

def expand_ipv6_address(address):
  """
  Expands abbreviated IPv6 addresses to their full colon separated hex format.
  For instance...
  
  ::
  
    >>> expand_ipv6_address("2001:db8::ff00:42:8329")
    "2001:0db8:0000:0000:0000:ff00:0042:8329"
    
    >>> expand_ipv6_address("::")
    "0000:0000:0000:0000:0000:0000:0000:0000"
  
  :param str address: IPv6 address to be expanded
  
  :raises: **ValueError** if the address can't be expanded due to being malformed
  """
  
  if not is_valid_ipv6_address(address):
    raise ValueError("'%s' isn't a valid IPv6 address" % address)
  
  # expands collapsed groupings, there can only be a single '::' in a valid
  # address
  if "::" in address:
    missing_groups = 7 - address.count(":")
    address = address.replace("::", "::" + ":" * missing_groups)
  
  # inserts missing zeros
  for index in xrange(8):
    start = index * 5
    end = address.index(":", start) if index != 7 else len(address)
    missing_zeros = 4 - (end - start)
    
    if missing_zeros > 0:
      address = address[:start] + "0" * missing_zeros + address[start:]
  
  return address

def get_mask(bits):
  """
  Provides the IPv4 mask for a given number of bits, in the dotted-quad format.
  
  :param int bits: number of bits to be converted
  
  :returns: **str** with the subnet mask representation for this many bits
  
  :raises: **ValueError** if given a number of bits outside the range of 0-32
  """
  
  if bits > 32 or bits < 0:
    raise ValueError("A mask can only be 0-32 bits, got %i" % bits)
  elif bits == 32:
    return FULL_IPv4_MASK
  
  # get the binary representation of the mask
  mask_bin = get_binary(2 ** bits - 1, 32)[::-1]
  
  # breaks it into eight character groupings
  octets = [mask_bin[8 * i:8 * (i + 1)] for i in xrange(4)]
  
  # converts each octet into its integer value
  return ".".join([str(int(octet, 2)) for octet in octets])

def get_masked_bits(mask):
  """
  Provides the number of bits that an IPv4 subnet mask represents. Note that
  not all masks can be represented by a bit count.
  
  :param str mask: mask to be converted
  
  :returns: **int** with the number of bits represented by the mask
  
  :raises: **ValueError** if the mask is invalid or can't be converted
  """
  
  if not is_valid_ip_address(mask):
    raise ValueError("'%s' is an invalid subnet mask" % mask)
  
  # converts octets to binary representation
  mask_bin = get_address_binary(mask)
  mask_match = re.match("^(1*)(0*)$", mask_bin)
  
  if mask_match:
    return 32 - len(mask_match.groups()[1])
  else:
    raise ValueError("Unable to convert mask to a bit count: %s" % mask)

def get_mask_ipv6(bits):
  """
  Provides the IPv6 mask for a given number of bits, in the hex colon-delimited
  format.
  
  :param int bits: number of bits to be converted
  
  :returns: **str** with the subnet mask representation for this many bits
  
  :raises: **ValueError** if given a number of bits outside the range of 0-128
  """
  
  if bits > 128 or bits < 0:
    raise ValueError("A mask can only be 0-128 bits, got %i" % bits)
  elif bits == 128:
    return FULL_IPv6_MASK
  
  # get the binary representation of the mask
  mask_bin = get_binary(2 ** bits - 1, 128)[::-1]
  
  # breaks it into sixteen character groupings
  groupings = [mask_bin[16 * i:16 * (i + 1)] for i in xrange(8)]
  
  # converts each group into its hex value
  return ":".join(["%04x" % int(group, 2) for group in groupings]).upper()

def get_binary(value, bits):
  """
  Provides the given value as a binary string, padded with zeros to the given
  number of bits.
  
  :param int value: value to be converted
  :param int bits: number of bits to pad to
  """
  
  # http://www.daniweb.com/code/snippet216539.html
  return "".join([str((value >> y) & 1) for y in range(bits - 1, -1, -1)])

def get_address_binary(address):
  """
  Provides the binary value for an IPv4 or IPv6 address.
  
  :returns: **str** with the binary representation of this address
  
  :raises: **ValueError** if address is neither an IPv4 nor IPv6 address
  """
  
  if is_valid_ip_address(address):
    return "".join([get_binary(int(octet), 8) for octet in address.split(".")])
  elif is_valid_ipv6_address(address):
    address = expand_ipv6_address(address)
    return "".join([get_binary(int(grouping, 16), 16) for grouping in address.split(":")])
  else:
    raise ValueError("'%s' is neither an IPv4 or IPv6 address" % address)

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
  
  :returns: **True** if both strings are equal, **False** otherwise.
  """
  
  return (
    hmac_sha256(CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE, x) ==
    hmac_sha256(CRYPTOVARIABLE_EQUALITY_COMPARISON_NONCE, y))
