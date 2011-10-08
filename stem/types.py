"""
Classes for miscellaneous tor object. This includes...

types.Version - Tor versioning information.
  * get_version(versionStr)
    Converts a version string to a types.Version instance.
"""

import re

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
  
  def __init__(self, major, minor, micro, patch = None, status = None):
    self.major = major
    self.minor = minor
    self.micro = micro
    self.patch = patch
    self.status = status
  
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
    Simple comparision of versions. An undefined patch level is treated as zero
    and status tags are compared lexically (as per the version spec).
    """
    
    if not isinstance(other, Version):
      raise ValueError("types.Version can only be compared with other Version instances")
    
    for attr in ("major", "minor", "micro", "patch"):
      my_version = max(0, self.__dict__[attr])
      other_version = max(0, other.__dict__[attr])
      
      if my_version > other_version: return 1
      elif my_version < other_version: return -1
    
    my_status = self.status if self.status else ""
    other_status = other.status if other.status else ""
    
    return cmp(my_status, other_status)

def get_version(version_str):
  """
  Parses a version string, providing back a types.Version instance.
  
  Arguments:
    version_str (str) - representation of a tor version (ex. "0.2.2.23-alpha")
  
  Returns:
    types.Version instance
  
  Throws:
    ValueError if input isn't a valid tor version
  """
  
  if not isinstance(version_str, str):
    raise ValueError("argument is not a string")
  
  m = re.match(r'^([0-9]+).([0-9]+).([0-9]+)(.[0-9]+)?(-\S*)?$', version_str)
  
  if m:
    major, minor, micro, patch, status = m.groups()
    
    # The patch and status matches are optional (may be None) and have an extra
    # proceeding period or dash if they exist. Stripping those off.
    
    if patch: patch = int(patch[1:])
    if status: status = status[1:]
    
    return Version(int(major), int(minor), int(micro), patch, status)
  else: raise ValueError("'%s' isn't a properly formatted tor version" % version_str)

