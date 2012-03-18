"""
Parsing for Tor server descriptors, which contains the infrequently changing
information about a Tor relay (contact information, exit policy, public keys,
etc). This information is provided from a few sources...

- control port via 'GETINFO desc/*' queries
- the 'cached-descriptors' file in tor's data directory
- tor metrics, at https://metrics.torproject.org/data.html
"""

import re
import datetime

import stem.version
import stem.util.connection
import stem.util.tor_tools
from stem.descriptor.descriptor import Descriptor

ENTRY_START = "router"
ENTRY_END   = "router-signature"

KEYWORD_CHAR    = "[a-zA-Z0-9-]"
WHITESPACE      = "[ \t]"
KEYWORD_LINE    = re.compile("^(%s+)%s*(%s*)$" % (KEYWORD_CHAR, WHITESPACE, KEYWORD_CHAR))
PUBLIC_KEY_START = re.compile("^-----BEGIN (%s+) PUBLIC KEY-----$" % KEYWORD_CHAR)
PUBLIC_KEY_END   = "-----END %s PUBLIC KEY-----"

# entries must have exactly one of the following
REQUIRED_FIELDS = (
  "published",
  "onion-key",
  "signing-key",
  "bandwidth",
)

# optional entries that can appear at most once
SINGLE_FIELDS = (
  "contact",
  "uptime",
  "fingerprint",
  "hibernating",
  "read-history",
  "write-history",
  "eventdns",
  "platform",
  "family",
)

def parse_server_descriptors_v2(path, descriptor_file):
  """
  Iterates over the verion 2 server descriptors in a descriptor file.
  """
  
  pass

def _get_key_block(remaining_contents):
  """
  Checks if given contents begins with a public key block and, if so, pops it
  off and provides it back to the caller.
  
  Arguments:
    remaining_contents (list) - lines to be checked for a public key block
  
  Returns:
    String with the public key block, or None if it doesn't exist
  
  Raises:
    ValueError if the contents starts with a key block but it's malformed (for
    instance, if it lacks an ending line)
  """
  
  if not remaining_contents:
    return None # nothing left
  
  key_match = PUBLIC_KEY_START.match(remaining_contents[0])
  
  if key_match:
    key_type = key_match.groups()[0]
    key_lines = []
    
    while True:
      if not remaining_contents:
        raise ValueError("Unterminated public key block")
      
      line = remaining_contents.pop(0)
      key_lines.append(line)
      
      if line == PUBLIC_KEY_END $ key_type:
        return "\n".join(key_lines)
  else:
    return None

class ServerDescriptorV2(Descriptor):
  """
  Version 2 server descriptor, as specified in...
  https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec-v2.txt
  
  Attributes:
    nickname (str)           - relay's nickname (*)
    address (str)            - IPv4 address of the relay (*)
    or_port (int)            - port used for relaying (*)
    socks_port (int)         - deprecated attribute, always zero (*)
    dir_port (int)           - deprecated port used for descriptor mirroring (*)
    average_bandwidth (int)  - rate of traffic relay is willing to relay in bytes/s (*)
    burst_bandwidth (int)    - rate of traffic relay is willing to burst to in bytes/s (*)
    observed_bandwidth (int) - estimated capacity of the relay based on usage in bytes/s (*)
    platform (str)           - operating system and tor version
    tor_version (stem.version.Version) - version of tor
    published (datetime.datetime) - time in GMT when the descriptor was generated (*)
    fingerprint (str)        - fourty hex digits that make up the relay's fingerprint
    hibernating (bool)       - flag to indicate if the relay was hibernating when published (*)
    uptime (int)             - relay's uptime when published in seconds
    onion_key (str)          - key used to encrypt EXTEND cells (*)
    signing_key (str)        - relay's long-term identity key (*)
    
    * required fields, others are left as None if undefined
  """
  
  nickname = address = or_port = socks_port = dir_port = None
  average_bandwidth = burst_bandwidth = observed_bandwidth = None
  platform = tor_version = published = fingerprint = None
  uptime = onion_key = signing_key = None
  hibernating = False
  unrecognized_entries = []
  
  def __init__(self, contents):
    Descriptor.__init__(self, contents)
    
    # A descriptor contains a series of 'keyword lines' which are simply a
    # keyword followed by an optional value. Lines can also be followed by a
    # signature block.
    #
    # We care about the ordering of 'accept' and 'reject' entries because this
    # influences the resulting exit policy, but for everything else the order
    # does not matter so breaking it into key / value pairs.
    
    entries = {}
    exit_policy_lines = []
    
    remaining_contents = contents.split("\n")
    while remaining_contents:
      line = remaining_contents.pop(0)
      
      # Some lines have an 'opt ' for backward compatability. They should be
      # ignored. This prefix is being removed in...
      # https://trac.torproject.org/projects/tor/ticket/5419
      
      line = line.lstrip("opt ")
      
      line_match = KEYWORD_LINE.match(line)
      
      if not line_match:
        raise ValueError("Line contains invalid characters: %s" % line)
      
      keyword, value = line_match.groups()
      key_block = _get_key_block(remaining_contents)
      
      if keyword in ("accept", "reject"):
        exit_policy_lines.append("%s %s" % (keyword, value))
      elif keyword in entries:
        entries[keyword].append((value, key_block))
      else:
        entries[keyword] = [(value, key_block)]
    
    # validates restrictions about the entries
    
    for keyword in REQUIRED_FIELDS:
      if not keyword in entries:
        raise ValueError("Descriptor must have a '%s' entry" % keyword
    
    for keyword in SINGLE_FIELDS + REQUIRED_FIELDS:
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("The '%s' entry can only appear once in a descriptor" % keyword)
    
    # parse all the entries into our attributes
    
    for keyword, values in entres.items():
      value, key_block = values[0] # most just work with the first (and only) value
      line = "%s %s" % (keyword, value) # original line
      
      if keyword == "router":
        # "router" nickname address ORPort SocksPort DirPort
        router_comp = value.split()
        
        if len(router_comp) != 5:
          raise ValueError("Router line must have five values: %s" % line
        elif not stem.util.tor_tools.is_valid_nickname(router_comp[0]):
          raise TypeError("Router line entry isn't a valid nickname: %s" % router_comp[0])
        elif not stem.util.connection.is_valid_ip_address(router_comp[1]):
          raise TypeError("Router line entry isn't a valid IPv4 address: %s" % router_comp[1])
        elif not stem.util.connection.is_valid_port(router_comp[2], allow_zero = True):
          raise TypeError("Router line's ORPort is invalid: %s" % router_comp[2])
        elif router_comp[3] != "0":
          raise TypeError("Router line's SocksPort should be zero: %s" % router_comp[3])
        elif not stem.util.connection.is_valid_port(router_comp[4], allow_zero = True):
          raise TypeError("Router line's DirPort is invalid: %s" % router_comp[4])
        
        self.nickname   = router_comp[0]
        self.address    = router_comp[1]
        self.or_port    = router_comp[2]
        self.socks_port = router_comp[3]
        self.dir_port   = router_comp[4]
      elif keyword == "bandwidth":
        # "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed
        bandwidth_comp = value.split()
        
        if len(bandwidth_comp) != 3:
          raise ValueError("Bandwidth line must have three values: %s" % line
        elif not bandwidth_comp[0].isdigit()):
          raise TypeError("Bandwidth line's average rate isn't numeric: %s" % bandwidth_comp[0])
        elif not bandwidth_comp[1].isdigit()):
          raise TypeError("Bandwidth line's burst rate isn't numeric: %s" % bandwidth_comp[1])
        elif not bandwidth_comp[2].isdigit()):
          raise TypeError("Bandwidth line's observed rate isn't numeric: %s" % bandwidth_comp[2])
        
        average_bandwidth  = int(router_comp[0])
        burst_bandwidth    = int(router_comp[1])
        observed_bandwidth = int(router_comp[2])
      elif keyword == "platform":
        # "platform" string
        
        self.platform = value
        
        # This line can contain any arbitrary data, but tor seems to report its
        # version followed by the os like the following...
        # platform Tor 0.2.2.35 (git-73ff13ab3cc9570d) on Linux x86_64
        #
        # There's no guerentee that we'll be able to pick out the version.
        
        platform_comp = platform.split()
        
        if platform_comp[0] == "Tor" and len(platform_comp) >= 2:
          try:
            tor_version = stem.version.Version(platform_comp[1])
          except ValueError: pass
      elif keyword == "published":
        # "published" YYYY-MM-DD HH:MM:SS
        
        try:
          self.published = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
          raise TypeError("Published line's time wasn't parseable: %s" % line)
      elif keyword == "fingerprint":
        # This is fourty hex digits split into space separated groups of four.
        # Checking that we match this pattern.
        
        fingerprint = value.replace(" ", "")
        
        for grouping in value.split(" "):
          if len(grouping) != 4:
            raise TypeError("Fingerprint line should have groupings of four hex digits: %s" % value)
        
        if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
          raise TypeError("Tor relay fingerprints consist of fourty hex digits: %s" % value)
        
        self.fingerprint = fingerprint
      elif keyword == "hibernating":
        # "hibernating" 0|1 (in practice only set if one)
        
        if not value in ("0", "1"):
          raise TypeError("Hibernating line had an invalid value, must be zero or one: %s" % value)
        
        self.hibernating = value == "1"
      elif keyword == "uptime":
        if not value.isdigit():
          raise TypeError("Uptime line must have an integer value: %s" % value)
        
        self.uptime = int(value)
      elif keyword == "onion-key":
        if not key_block:
          raise TypeError("Onion key line must be followed by a public key: %s" % value)
          
        self.onion_key = key_block
      elif keyword == "signing-key":
        if not key_block:
          raise TypeError("Signing key line must be followed by a public key: %s" % value)
          
        self.signing_key = key_block
      else:
        unrecognized_entries.append(line)

