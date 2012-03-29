"""
Parsing for Tor server descriptors, which contains the infrequently changing
information about a Tor relay (contact information, exit policy, public keys,
etc). This information is provided from a few sources...

- control port via 'GETINFO desc/*' queries
- the 'cached-descriptors' file in tor's data directory
- tor metrics, at https://metrics.torproject.org/data.html

parse_file_v3 - Iterates over the server descriptors in a file.
ServerDescriptorV3 - Tor server descriptor, version 3.
  |- get_unrecognized_lines - lines with unrecognized content
  |- get_annotations - dictionary of content prior to the descriptor entry
  |- get_annotation_lines - lines that provided the annotations
  +- is_valid - checks the signature against the descriptor content
"""

import re
import datetime

import stem.descriptor
import stem.version
import stem.util.connection
import stem.util.tor_tools
import stem.util.log as log

ENTRY_START = "router"
ENTRY_END   = "router-signature"

KEYWORD_CHAR    = "a-zA-Z0-9-"
WHITESPACE      = " \t"
KEYWORD_LINE    = re.compile("^([%s]+)[%s]*(.*)$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_START = re.compile("^-----BEGIN ([%s%s]+)-----$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END   = "-----END %s-----"

# entries must have exactly one of the following
REQUIRED_FIELDS = (
  "router",
  "bandwidth",
  "published",
  "onion-key",
  "signing-key",
  "router-signature",
)

# optional entries that can appear at most once
SINGLE_FIELDS = (
  "platform",
  "fingerprint",
  "hibernating",
  "uptime",
  "contact",
  "read-history",
  "write-history",
  "eventdns",
  "family",
  "caches-extra-info",
  "extra-info-digest",
  "hidden-service-dir",
  "protocols",
  "allow-single-hop-exits",
)

def parse_file_v3(descriptor_file, validate = True):
  """
  Iterates over the version 3 server descriptors in a file.
  
  Arguments:
    descriptor_file (file) - file with descriptor content
    validate (bool)        - checks the validity of the descriptor's content if
                             True, skips these checks otherwise
  
  Returns:
    iterator for ServerDescriptorV3 instances in the file
  
  Raises:
    ValueError if the contents is malformed and validate is True
    IOError if the file can't be read
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
  #
  # Any annotations after the last server descriptor is ignored (never provided
  # to the caller).
  
  while True:
    annotations = _read_until_keyword(ENTRY_START, descriptor_file)
    descriptor_content = _read_until_keyword(ENTRY_END, descriptor_file)
    
    # we've reached the 'router-signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    descriptor_content += _read_until_keyword(block_end_prefix, descriptor_file, True)
    
    if descriptor_content:
      # strip newlines from annotations
      annotations = map(str.strip, annotations)
      
      descriptor_text = "".join(descriptor_content)
      descriptor = ServerDescriptorV3(descriptor_text, validate, annotations)
      yield descriptor
    else: break # done parsing descriptors

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
  
  while True:
    last_position = descriptor_file.tell()
    line = descriptor_file.readline()
    if not line: break # EOF
    
    if " " in line: line_keyword = line.split(" ", 1)[0]
    else: line_keyword = line.strip()
    
    if line_keyword == keyword:
      if inclusive: content.append(line)
      else: descriptor_file.seek(last_position)
      
      break
    else:
      content.append(line)
  
  return content

def _get_pseudo_pgp_block(remaining_contents):
  """
  Checks if given contents begins with a pseudo-Open-PGP-style block and, if
  so, pops it off and provides it back to the caller.
  
  Arguments:
    remaining_contents (list) - lines to be checked for a public key block
  
  Returns:
    str with the armor wrapped contents or None if it doesn't exist
  
  Raises:
    ValueError if the contents starts with a key block but it's malformed (for
    instance, if it lacks an ending line)
  """
  
  if not remaining_contents:
    return None # nothing left
  
  block_match = PGP_BLOCK_START.match(remaining_contents[0])
  
  if block_match:
    block_type = block_match.groups()[0]
    block_lines = []
    
    while True:
      if not remaining_contents:
        raise ValueError("Unterminated pgp style block")
      
      line = remaining_contents.pop(0)
      block_lines.append(line)
      
      if line == PGP_BLOCK_END % block_type:
        return "\n".join(block_lines)
  else:
    return None

class ServerDescriptorV3(stem.descriptor.Descriptor):
  """
  Version 3 server descriptor, as specified in...
  https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt
  
  Attributes:
    nickname (str)           - relay's nickname (*)
    fingerprint (str)        - fourty hex digits that make up the relay's fingerprint
    address (str)            - IPv4 address of the relay (*)
    or_port (int)            - port used for relaying (*)
    socks_port (int)         - (deprecated) always zero (*)
    dir_port (int)           - deprecated port used for descriptor mirroring (*)
    platform (str)           - operating system and tor version
    tor_version (stem.version.Version) - version of tor
    operating_system (str)   - relay's operating system
    uptime (int)             - relay's uptime when published in seconds
    published (datetime.datetime) - time in GMT when the descriptor was generated (*)
    contact (str)            - relay's contact information
    link_protocols (list)    - link protocols supported by the relay
    circuit_protocols (list) - circuit protocols supported by the relay
    hibernating (bool)       - flag to indicate if the relay was hibernating when published (*)
    allow_single_hop_exits (bool) - flag to indicate if single hop exiting is allowed from it (*)
    extra_info_cache (bool)  - flag to indicate if it's a mirror for extra-info documents (*)
    extra_info_digest (str)  - hex encoded digest of our extra-info document
    hidden_service_dir (list) - hidden service descriptor versions that it stores
    exit_policy (stem.exit_policy.ExitPolicy) - relay's stated exit policy
    family (list)            - nicknames or fingerprints of relays it has a declared family with (*)
    average_bandwidth (int)  - rate of traffic relay is willing to relay in bytes/s (*)
    burst_bandwidth (int)    - rate of traffic relay is willing to burst to in bytes/s (*)
    observed_bandwidth (int) - estimated capacity of the relay based on usage in bytes/s (*)
    read_history (str)       - (deprecated) always unset
    write_history (str)      - (deprecated) always unset
    eventdns (bool)          - (deprecated) always unset (*)
    onion_key (str)          - key used to encrypt EXTEND cells (*)
    signing_key (str)        - relay's long-term identity key (*)
    signature (str)          - signature for this descriptor (*)
    
    (*) required fields, others are left as None if undefined
  """
  
  def __init__(self, contents, validate = True, annotations = None):
    """
    Version 3 server descriptor constructor, created from an individual relay's
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
    
    stem.descriptor.Descriptor.__init__(self, contents)
    
    self.nickname = None
    self.fingerprint = None
    self.address = None
    self.or_port = None
    self.socks_port = None
    self.dir_port = None
    self.platform = None
    self.tor_version = None
    self.operating_system = None
    self.uptime = None
    self.published = None
    self.contact = None
    self.link_protocols = None
    self.circuit_protocols = None
    self.hibernating = False
    self.allow_single_hop_exits = False
    self.extra_info_cache = False
    self.extra_info_digest = None
    self.hidden_service_dir = None
    self.family = []
    self.average_bandwidth = None
    self.burst_bandwidth = None
    self.observed_bandwidth = None
    self.read_history = None
    self.write_history = None
    self.eventdns = True
    self.onion_key = None
    self.signing_key = None
    self.signature = None
    
    # TODO: Until we have a proper ExitPolicy class this is just a list of the
    # exit policy strings...
    
    self.exit_policy = []
    
    self._unrecognized_lines = []
    
    if annotations:
      self._annotation_lines = annotations
      self._annotation_dict = {}
      
      for line in annotations:
        if " " in line:
          key, value = line.split(" ", 1)
          self._annotation_dict[key] = value
        else: self._annotation_dict[line] = None
    else:
      self._annotation_lines = []
      self._annotation_dict = {}
    
    # A descriptor contains a series of 'keyword lines' which are simply a
    # keyword followed by an optional value. Lines can also be followed by a
    # signature block.
    #
    # We care about the ordering of 'accept' and 'reject' entries because this
    # influences the resulting exit policy, but for everything else the order
    # does not matter so breaking it into key / value pairs.
    
    entries = {}
    remaining_contents = contents.split("\n")
    first_entry, last_entry = remaining_contents[0], remaining_contents[0]
    while remaining_contents:
      line = remaining_contents.pop(0)
      
      # last line can be empty
      if not line and not remaining_contents: continue
      last_entry = line
      
      # Some lines have an 'opt ' for backward compatability. They should be
      # ignored. This prefix is being removed in...
      # https://trac.torproject.org/projects/tor/ticket/5124
      
      if line.startswith("opt "): line = line[4:]
      
      line_match = KEYWORD_LINE.match(line)
      
      if not line_match:
        if not validate: continue
        raise ValueError("Line contains invalid characters: %s" % line)
      
      keyword, value = line_match.groups()
      
      try:
        block_contents = _get_pseudo_pgp_block(remaining_contents)
      except ValueError, exc:
        if not validate: continue
        raise exc
      
      if keyword in ("accept", "reject"):
        self.exit_policy.append("%s %s" % (keyword, value))
      elif keyword in entries:
        entries[keyword].append((value, block_contents))
      else:
        entries[keyword] = [(value, block_contents)]
    
    # validates restrictions about the entries
    if validate:
      for keyword in REQUIRED_FIELDS:
        if not keyword in entries:
          raise ValueError("Descriptor must have a '%s' entry" % keyword)
      
      for keyword in SINGLE_FIELDS + REQUIRED_FIELDS:
        if keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in a descriptor" % keyword)
      
      if not first_entry.startswith(ENTRY_START):
        raise ValueError("Descriptor must start with a '%s' entry" % ENTRY_START)
      elif not last_entry.startswith(ENTRY_END):
        raise ValueError("Descriptor must end with a '%s' entry" % ENTRY_END)
      elif not self.exit_policy:
        raise ValueError("Descriptor must have at least one 'accept' or 'reject' entry")
    
    # parse all the entries into our attributes
    for keyword, values in entries.items():
      # most just work with the first (and only) value
      value, block_contents = values[0]
      
      line = "%s %s" % (keyword, value) # original line
      if block_contents: line += "\n%s" % block_contents
      
      if keyword == "router":
        # "router" nickname address ORPort SocksPort DirPort
        router_comp = value.split()
        
        if len(router_comp) < 5:
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
        elif not (router_comp[2].isdigit() and router_comp[3].isdigit() and router_comp[4].isdigit()):
          continue
        
        self.nickname   = router_comp[0]
        self.address    = router_comp[1]
        self.or_port    = int(router_comp[2])
        self.socks_port = int(router_comp[3])
        self.dir_port   = int(router_comp[4])
      elif keyword == "bandwidth":
        # "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed
        bandwidth_comp = value.split()
        
        if len(bandwidth_comp) < 3:
          if not validate: continue
          raise ValueError("Bandwidth line must have three values: %s" % line)
        
        if not bandwidth_comp[0].isdigit():
          if not validate: continue
          raise ValueError("Bandwidth line's average rate isn't numeric: %s" % bandwidth_comp[0])
        elif not bandwidth_comp[1].isdigit():
          if not validate: continue
          raise ValueError("Bandwidth line's burst rate isn't numeric: %s" % bandwidth_comp[1])
        elif not bandwidth_comp[2].isdigit():
          if not validate: continue
          raise ValueError("Bandwidth line's observed rate isn't numeric: %s" % bandwidth_comp[2])
        
        self.average_bandwidth  = int(bandwidth_comp[0])
        self.burst_bandwidth    = int(bandwidth_comp[1])
        self.observed_bandwidth = int(bandwidth_comp[2])
      elif keyword == "platform":
        # "platform" string
        
        self.platform = value
        
        # This line can contain any arbitrary data, but tor seems to report its
        # version followed by the os like the following...
        # platform Tor 0.2.2.35 (git-73ff13ab3cc9570d) on Linux x86_64
        #
        # There's no guarantee that we'll be able to pick these out the
        # version, but might as well try to save our caller the effot.
        
        platform_match = re.match("^Tor (\S*).* on (.*)$", self.platform)
        
        if platform_match:
          version_str, self.operating_system = platform_match.groups()
          
          try:
            self.tor_version = stem.version.Version(version_str)
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
      elif keyword == "allow-single-hop-exits":
        self.allow_single_hop_exits = True
      elif keyword == "caches-extra-info":
        self.extra_info_cache = True
      elif keyword == "extra-info-digest":
        # this is fourty hex digits which just so happens to be the same a
        # fingerprint
        
        if validate and not stem.util.tor_tools.is_valid_fingerprint(value):
          raise ValueError("Extra-info digests should consist of fourty hex digits: %s" % value)
        
        self.extra_info_digest = value
      elif keyword == "hidden-service-dir":
        if value:
          self.hidden_service_dir = value.split(" ")
        else:
          self.hidden_service_dir = ["2"]
      elif keyword == "uptime":
        if not value.isdigit():
          if not validate: continue
          raise ValueError("Uptime line must have an integer value: %s" % value)
        
        self.uptime = int(value)
      elif keyword == "onion-key":
        if validate and not block_contents:
          raise ValueError("Onion key line must be followed by a public key: %s" % line)
        
        self.onion_key = block_contents
      elif keyword == "signing-key":
        if validate and not block_contents:
          raise ValueError("Signing key line must be followed by a public key: %s" % line)
        
        self.signing_key = block_contents
      elif keyword == "router-signature":
        if validate and not block_contents:
          raise ValueError("Router signature line must be followed by a signature block: %s" % line)
        
        self.signature = block_contents
      elif keyword == "contact":
        self.contact = value
      elif keyword == "protocols":
        protocols_match = re.match("^Link (.*) Circuit (.*)$", value)
        
        if protocols_match:
          link_versions, circuit_versions = protocols_match.groups()
          self.link_protocols = link_versions.split(" ")
          self.circuit_protocols = circuit_versions.split(" ")
        elif validate:
          raise ValueError("Protocols line did not match the expected pattern: %s" % line)
      elif keyword == "family":
        self.family = value.split(" ")
      elif keyword == "read-history":
        log.info("Read an unexpected 'read-history' line in a v3 server descriptor. These should only appear in extra-info. line: %s" % line)
        self.read_history = value
      elif keyword == "write-history":
        log.info("Read an unexpected 'write-history' line in a v3 server descriptor. These should only appear in extra-info. line: %s" % line)
        self.write_history = value
      elif keyword == "eventdns":
        log.info("Read an unexpected 'eventdns' line in a v3 server descriptor. These should be deprecated. line: %s" % line)
        self.eventdns = value == "1"
      else:
        self._unrecognized_lines.append(line)
  
  def get_unrecognized_lines(self):
    return list(self._unrecognized_lines)
  
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

