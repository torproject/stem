"""
Class representations for a variety of tor objects. These are most commonly
return values rather than being instantiated by users directly.

Version - Tor versioning information.
  |- __str__ - string representation
  +- __cmp__ - compares with another Version
"""

import re
import socket
import logging
import threading

LOGGER = logging.getLogger("stem")

class Version:
  """
  Comparable tor version, as per the 'new version' of the version-spec...
  https://gitweb.torproject.org/torspec.git/blob/HEAD:/version-spec.txt
  
  Attributes:
    major (int)  - major version
    minor (int)  - minor version
    micro (int)  - micro version
    patch (int)  - optional patch level (None if undefined)
    status (str) - optional status tag without the preceding dash such as
                   'alpha', 'beta-dev', etc (None if undefined)
  """
  
  def __init__(self, version_str):
    """
    Parses a valid tor version string, for instance "0.1.4" or
    "0.2.2.23-alpha".
    
    Raises:
      ValueError if input isn't a valid tor version
    """
    
    m = re.match(r'^([0-9]+).([0-9]+).([0-9]+)(.[0-9]+)?(-\S*)?$', version_str)
    
    if m:
      major, minor, micro, patch, status = m.groups()
      
      # The patch and status matches are optional (may be None) and have an extra
      # proceeding period or dash if they exist. Stripping those off.
      
      if patch: patch = int(patch[1:])
      if status: status = status[1:]
      
      self.major = int(major)
      self.minor = int(minor)
      self.micro = int(micro)
      self.patch = patch
      self.status = status
    else: raise ValueError("'%s' isn't a properly formatted tor version" % version_str)
  
  def __str__(self):
    """
    Provides the normal representation for the version, for instance:
    "0.2.2.23-alpha"
    """
    
    suffix = ""
    
    if self.patch:
      suffix += ".%i" % self.patch
    
    if self.status:
      suffix += "-%s" % self.status
    
    return "%i.%i.%i%s" % (self.major, self.minor, self.micro, suffix)
  
  def __cmp__(self, other):
    """
    Simple comparison of versions. An undefined patch level is treated as zero
    and status tags are compared lexically (as per the version spec).
    """
    
    if not isinstance(other, Version):
      return 1 # this is also used for equality checks
    
    for attr in ("major", "minor", "micro", "patch"):
      my_version = max(0, self.__dict__[attr])
      other_version = max(0, other.__dict__[attr])
      
      if my_version > other_version: return 1
      elif my_version < other_version: return -1
    
    my_status = self.status if self.status else ""
    other_status = other.status if other.status else ""
    
    return cmp(my_status, other_status)

# TODO: version requirements will probably be moved to another module later
REQ_GETINFO_CONFIG_TEXT = Version("0.2.2.7-alpha")
REQ_CONTROL_SOCKET = Version("0.2.0.30")

