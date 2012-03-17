"""
Parsing for Tor server descriptors, which contains the infrequently changing
information about a Tor relay (contact information, exit policy, public keys,
etc). This information is provided from a few sources...

- control port via 'GETINFO desc/*' queries
- the 'cached-descriptors' file in tor's data directory
- tor metrics, at https://metrics.torproject.org/data.html
"""

import re

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
    nickname (str)   - relay's nickname (*)
    address (str)    - IPv4 address of the relay (*)
    or_port (int)    - port used for relaying (*)
    socks_port (int) - deprecated attribute, always zero (*)
    dir_port (int)   - deprecated port used for descriptor mirroring (*)
    
    * required fields
  """
  
  nickname = None
  address = None
  or_port = None
  socks_port = None
  dir_port = None
  
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
      line_match = KEYWORD_LINE.match()
      
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
        
        # TODO: also check validity of other fields
        # Fingerprint = "$" 40*HEXDIG
        # NicknameChar = "a"-"z" / "A"-"Z" / "0" - "9"
        # Nickname = 1*19 NicknameChar
        
        self.nickname   = router_comp[0]
        self.address    = router_comp[1]
        self.or_port    = router_comp[2]
        self.socks_port = router_comp[3]
        self.dir_port   = router_comp[4]

