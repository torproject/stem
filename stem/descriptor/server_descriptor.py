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
SIGNATURE_START = re.compile("^-----BEGIN %s+ PUBLIC KEY-----$" % KEYWORD_CHAR)
SIGNATURE_END   = re.compile("^-----END %s+ PUBLIC KEY-----$" % KEYWORD_CHAR)

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
    
    * required fields, others are left as None if undefined
  """
  
  nickname = address = or_port = socks_port = dir_port = None
  average_bandwidth = burst_bandwidth = observed_bandwidth = None
  platform = tor_version = None
  published = None
  
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
    
    for line in contents.split("\n"):
      # Some lines have an 'opt ' for backward compatability. They should be
      # ignored. This prefix is being removed in...
      # https://trac.torproject.org/projects/tor/ticket/5419
      
      line = line.lstrip("opt ")
      
      line_match = KEYWORD_LINE.match(line)
      
      if not line_match:
        raise ValueError("Line contains invalid characters: %s" % line)
      
      keyword, value = line_match.groups()
      
      if keyword in ("accept", "reject"):
        exit_policy_lines.append("%s %s" % (keyword, value))
      elif keyword in entries:
        entries[keyword].append(value)
      else:
        entries[keyword] = [value]
    
    # validates restrictions about the entries
    
    for keyword in REQUIRED_FIELDS:
      if not keyword in entries:
        raise ValueError("Descriptor must have a '%s' entry" % keyword
    
    for keyword in SINGLE_FIELDS + REQUIRED_FIELDS:
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("The '%s' entry can only appear once in a descriptor" % keyword)
    
    # parse all the entries into our attributes
    
    for keyword, values in entres.items():
      if keyword == "router":
        # "router" nickname address ORPort SocksPort DirPort
        router_comp = values[0].split()
        
        if len(router_comp) != 5:
          raise ValueError("Router line must have five values: router %s" % values[0]
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
        bandwidth_comp = values[0].split()
        
        if len(bandwidth_comp) != 3:
          raise ValueError("Bandwidth line must have three values: bandwidth %s" % values[0]
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
        
        self.platform = values[0]
        
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
          self.published = datetime.datetime.strptime(values[0], "%Y-%m-%d %H:%M:%S")
        except ValueError:
          raise TypeError("Published line's time wasn't parseable: %s" % values[0])

