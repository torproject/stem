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
import stem.descriptor.descriptor

ENTRY_START = "router"
ENTRY_END   = "router-signature"

KEYWORD_CHAR    = "a-zA-Z0-9-"
WHITESPACE      = " \t"
KEYWORD_LINE    = re.compile("^([%s]+)[%s]*([%s]*)$" % (KEYWORD_CHAR, WHITESPACE, KEYWORD_CHAR))
PGP_BLOCK_START = re.compile("^-----BEGIN ([%s%s]+)-----$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END   = "-----END %s-----"

# entries must have exactly one of the following
# TODO: spec doesn't list 'router-signature', but that's a spec bug I should fix
REQUIRED_FIELDS = (
  "published",
  "onion-key",
  "signing-key",
  "bandwidth",
  "router-signature",
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
  
  # Cached descriptors consist of annotations followed by the descriptor
  # itself. For instance...
  #
  #   @downloaded-at 2012-03-14 16:31:05
  #   @source "145.53.65.130"
  #   router caerSidi 71.35.143.157 9001 0 0
  #   platform Tor 0.2.1.30 on Linux x86_64
  #   <rest of the descriptor content>
  #   router-signature
  #   -----BEGIN SIGNATURE-----
  #   <signature for the above descriptor>
  #   -----END SIGNATURE-----
  #
  # Metrics descriptor files are the same, but lack any annotations. The
  # following simply does the following...
  #
  #   - parse as annotations until we get to ENTRY_START
  #   - parse as descriptor content until we get to ENTRY_END followed by the
  #     end of the signature block
  #   - construct a descriptor and provide it back to the caller
  
  while descriptor_file:
    annotations = _read_until_keyword(ENTRY_START, descriptor_file)
    descriptor_content = _read_until_keyword(ENTRY_END, descriptor_file)
    
    # we've reached the 'router-signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    descriptor_content += _read_until_keyword(block_end_prefix, descriptor_file, True)
    
    # If the file has ending annotations (ie, non-descriptor text after the
    # last descriptor) then we won't have any descriptor content at this point.
    # This is fine. Those ending annotations are simply never returned to the
    # caller.
    
    if descriptor_content:
      descriptor = ServerDescriptorV2(descriptor_content, annotations = annotations)
      descriptor._set_path(path)
      yield descriptor

def _read_until_keyword(keyword, descriptor_file, inclusive = False):
  """
  Reads from the descriptor file until we get to the given keyword or reach the
  end of the file.
  
  Arguments:
    keyword (str)          - keyword we want to read until
    descriptor_file (file) - file with the descriptor content
    inclusive (bool)       - includes the line with the keyword if True
  
  Returns:
    list with the lines until we find the keyword
  """
  
  content = []
  
  while descriptor_file:
    last_position = descriptor_file.tell()
    line = descriptor_file.readline()
    
    if not line: continue # blank line
    elif " " in line: line_keyword = line.split(" ", 1)[0]
    else: line_keyword = line
    
    if line_keyword == keyword:
      if inclusive: content.append(line)
      else: descriptor_file.seek(last_position)
      
      break
    else:
      content.append(line)
  
  return content

def _get_psudo_pgp_block(remaining_contents):
  """
  Checks if given contents begins with a pseudo-Open-PGP-style block and, if
  so, pops it off and provides it back to the caller.
  
  Arguments:
    remaining_contents (list) - lines to be checked for a public key block
  
  Returns:
    (str, str) tuple with the block type and the armor wrapped contents, this
    returns (None, None) instead if it doesn't exist
  
  Raises:
    ValueError if the contents starts with a key block but it's malformed (for
    instance, if it lacks an ending line)
  """
  
  if not remaining_contents:
    return (None, None) # nothing left
  
  block_match = PGP_BLOCK_START.match(remaining_contents[0])
  
  if block_match:
    block_type = block_match.groups()[0]
    block_lines = []
    
    while True:
      if not remaining_contents:
        raise ValueError("Unterminated public key block")
      
      line = remaining_contents.pop(0)
      block_lines.append(line)
      
      if line == PGP_BLOCK_END % block_type:
        return block_type, "\n".join(block_lines)
  else:
    return (None, None)

class ServerDescriptorV2(stem.descriptor.descriptor.Descriptor):
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
    exit_policy (stem.exit_policy.ExitPolicy) - relay's stated exit policy
    published (datetime.datetime) - time in GMT when the descriptor was generated (*)
    fingerprint (str)        - fourty hex digits that make up the relay's fingerprint
    hibernating (bool)       - flag to indicate if the relay was hibernating when published (*)
    uptime (int)             - relay's uptime when published in seconds
    onion_key (str)          - key used to encrypt EXTEND cells (*)
    onion_key_type (str)     - block type of the onion_key, probably "RSA PUBLIC KEY" (*)
    signing_key (str)        - relay's long-term identity key (*)
    signing_key_type (str)   - block type of the signing_key, probably "RSA PUBLIC KEY" (*)
    router_sig (str)         - signature for this descriptor (*)
    router_sig_type (str)    - block type of the router_sig, probably "SIGNATURE" (*)
    contact (str)            - relay's contact information
    family (list)            - nicknames or fingerprints of relays it has a declared family with (*)
    
    * required fields, others are left as None if undefined
  """
  
  nickname = address = or_port = socks_port = dir_port = None
  average_bandwidth = burst_bandwidth = observed_bandwidth = None
  platform = tor_version = published = fingerprint = uptime = None
  onion_key = onion_key_type = signing_key = signing_key_type = None
  router_sig = router_sig_type = contact = None
  hibernating = False
  family = unrecognized_entries = []
  
  # TODO: Until we have a proper ExitPolicy class this is just a list of the
  # exit policy strings...
  
  exit_policy = []
  
  def __init__(self, contents, validate = True, annotations = None):
    """
    Version 2 server descriptor constructor, created from an individual relay's
    descriptor content (as provided by "GETINFO desc/*", cached descriptors,
    and metrics).
    
    By default this validates the descriptor's content as it's parsed. This
    validation can be disables to either improve performance or be accepting of
    malformed data.
    
    Arguments:
      contents (str)     - descriptor content provided by the relay
      validate (bool)    - checks the validity of the descriptor's content if
                           True, skips these checks otherwise
      annotations (list) - lines that appeared prior to the descriptor
    
    Raises:
      ValueError if the contents is malformed and validate is True
    """
    
    stem.descriptor.descriptor.Descriptor.__init__(self, contents)
    
    self._annotation_lines = annotations
    self._annotation_dict = {}
    
    for line in annotations:
      if " " in line:
        key, value = line.split(" ", 1)
        self._annotation_dict[key] = value
      else: self._annotation_dict[line] = None
    
    # A descriptor contains a series of 'keyword lines' which are simply a
    # keyword followed by an optional value. Lines can also be followed by a
    # signature block.
    #
    # We care about the ordering of 'accept' and 'reject' entries because this
    # influences the resulting exit policy, but for everything else the order
    # does not matter so breaking it into key / value pairs.
    
    entries = {}
    
    remaining_contents = contents.split("\n")
    while remaining_contents:
      line = remaining_contents.pop(0)
      
      # Some lines have an 'opt ' for backward compatability. They should be
      # ignored. This prefix is being removed in...
      # https://trac.torproject.org/projects/tor/ticket/5124
      
      line = line.lstrip("opt ")
      
      line_match = KEYWORD_LINE.match(line)
      
      if not line_match:
        if not validate: continue
        raise ValueError("Line contains invalid characters: %s" % line)
      
      keyword, value = line_match.groups()
      block_type, block_contents = _get_psudo_pgp_block(remaining_contents)
      
      if keyword in ("accept", "reject"):
        self.exit_policy.append("%s %s" % (keyword, value))
      elif keyword in entries:
        entries[keyword].append((value, block_type, block_contents))
      else:
        entries[keyword] = [(value, block_type, block_contents)]
    
    # validates restrictions about the entries
    
    if validate:
      for keyword in REQUIRED_FIELDS:
        if not keyword in entries:
          raise ValueError("Descriptor must have a '%s' entry" % keyword)
      
      for keyword in SINGLE_FIELDS + REQUIRED_FIELDS:
        if keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in a descriptor" % keyword)
    
    # parse all the entries into our attributes
    
    for keyword, values in entries.items():
      # most just work with the first (and only) value
      value, block_type, block_contents = values[0]
      
      line = "%s %s" % (keyword, value) # original line
      if block_contents: line += "\n%s" % block_contents
      
      if keyword == "router":
        # "router" nickname address ORPort SocksPort DirPort
        router_comp = value.split()
        
        if len(router_comp) != 5:
          if not validate: continue
          raise ValueError("Router line must have five values: %s" % line)
        
        if validate:
          if not stem.util.tor_tools.is_valid_nickname(router_comp[0]):
            raise ValueError("Router line entry isn't a valid nickname: %s" % router_comp[0])
          elif not stem.util.connection.is_valid_ip_address(router_comp[1]):
            raise ValueError("Router line entry isn't a valid IPv4 address: %s" % router_comp[1])
          elif not stem.util.connection.is_valid_port(router_comp[2], allow_zero = True):
            raise ValueError("Router line's ORPort is invalid: %s" % router_comp[2])
          elif router_comp[3] != "0":
            raise ValueError("Router line's SocksPort should be zero: %s" % router_comp[3])
          elif not stem.util.connection.is_valid_port(router_comp[4], allow_zero = True):
            raise ValueError("Router line's DirPort is invalid: %s" % router_comp[4])
        
        self.nickname   = router_comp[0]
        self.address    = router_comp[1]
        self.or_port    = router_comp[2]
        self.socks_port = router_comp[3]
        self.dir_port   = router_comp[4]
      elif keyword == "bandwidth":
        # "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed
        bandwidth_comp = value.split()
        
        if len(bandwidth_comp) != 3:
          if not validate: continue
          raise ValueError("Bandwidth line must have three values: %s" % line)
        
        if validate:
          if not bandwidth_comp[0].isdigit():
            raise ValueError("Bandwidth line's average rate isn't numeric: %s" % bandwidth_comp[0])
          elif not bandwidth_comp[1].isdigit():
            raise ValueError("Bandwidth line's burst rate isn't numeric: %s" % bandwidth_comp[1])
          elif not bandwidth_comp[2].isdigit():
            raise ValueError("Bandwidth line's observed rate isn't numeric: %s" % bandwidth_comp[2])
        
        self.average_bandwidth  = int(router_comp[0])
        self.burst_bandwidth    = int(router_comp[1])
        self.observed_bandwidth = int(router_comp[2])
      elif keyword == "platform":
        # "platform" string
        
        self.platform = value
        
        # This line can contain any arbitrary data, but tor seems to report its
        # version followed by the os like the following...
        # platform Tor 0.2.2.35 (git-73ff13ab3cc9570d) on Linux x86_64
        #
        # There's no guerentee that we'll be able to pick out the version.
        
        platform_comp = self.platform.split()
        
        if platform_comp[0] == "Tor" and len(platform_comp) >= 2:
          try:
            self.tor_version = stem.version.Version(platform_comp[1])
          except ValueError: pass
      elif keyword == "published":
        # "published" YYYY-MM-DD HH:MM:SS
        
        try:
          self.published = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
          if validate:
            raise ValueError("Published line's time wasn't parseable: %s" % line)
      elif keyword == "fingerprint":
        # This is fourty hex digits split into space separated groups of four.
        # Checking that we match this pattern.
        
        fingerprint = value.replace(" ", "")
        
        if validate:
          for grouping in value.split(" "):
            if len(grouping) != 4:
              raise ValueError("Fingerprint line should have groupings of four hex digits: %s" % value)
          
          if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
            raise ValueError("Tor relay fingerprints consist of fourty hex digits: %s" % value)
        
        self.fingerprint = fingerprint
      elif keyword == "hibernating":
        # "hibernating" 0|1 (in practice only set if one)
        
        if validate and not value in ("0", "1"):
          raise ValueError("Hibernating line had an invalid value, must be zero or one: %s" % value)
        
        self.hibernating = value == "1"
      elif keyword == "uptime":
        if not value.isdigit():
          if not validate: continue
          raise ValueError("Uptime line must have an integer value: %s" % value)
        
        self.uptime = int(value)
      elif keyword == "onion-key":
        if validate and (not block_type or not block_contents):
          raise ValueError("Onion key line must be followed by a public key: %s" % line)
        
        self.onion_key_type = block_type
        self.onion_key = block_contents
      elif keyword == "signing-key":
        if validate and (not block_type or not block_contents):
          raise ValueError("Signing key line must be followed by a public key: %s" % line)
        
        self.signing_key_type = block_type
        self.signing_key = block_contents
      elif keyword == "router-signature":
        if validate and (not block_type or not block_contents):
          raise ValueError("Router signature line must be followed by a signature block: %s" % line)
        
        self.router_sig_type = block_type
        self.router_sig = block_contents
      elif keyword == "contact":
        self.contact = value
      elif keyword == "family":
        self.family = value.split(" ")
      else:
        self.unrecognized_entries.append(line)
  
  def get_annotations(self):
    """
    Provides content that appeard prior to the descriptor. If this comes from
    the cached-descriptors file then this commonly contains content like...
    
      @downloaded-at 2012-03-18 21:18:29
      @source "173.254.216.66"
    
    Returns:
      dict with the key/value pairs in our annotations
    """
    
    return self._annotation_dict
  
  def get_annotation_lines(self):
    """
    Provides the lines of content that appeared prior to the descriptor. This
    is the same as the get_annotations() results, but with the unparsed lines
    and ordering retained.
    
    Returns:
      list with the lines of annotation that came before this descriptor
    """
    
    return self._annotation_lines
  
  def is_valid(self):
    """
    Validates that our content matches our signature.
    
    Returns:
      True if our signature matches our content, False otherwise
    """
    
    raise NotImplementedError # TODO: implement

