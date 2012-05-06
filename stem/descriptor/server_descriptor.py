"""
Parsing for Tor server descriptors, which contains the infrequently changing
information about a Tor relay (contact information, exit policy, public keys,
etc). This information is provided from a few sources...

- control port via 'GETINFO desc/*' queries
- the 'cached-descriptors' file in tor's data directory
- tor metrics, at https://metrics.torproject.org/data.html
- directory authorities and mirrors via their DirPort

parse_file - Iterates over the server descriptors in a file.
ServerDescriptor - Tor server descriptor.
  |  |- RelayDescriptor - Server descriptor for a relay.
  |  |  |- is_valid - checks the signature against the descriptor content
  |  |  +- digest - calculates the digest value for our content
  |  |
  |  +- BridgeDescriptor - Scrubbed server descriptor for a bridge.
  |     |- is_scrubbed - checks if our content has been properly scrubbed
  |     +- get_scrubbing_issues - description of issues with our scrubbing
  |
  |- get_unrecognized_lines - lines with unrecognized content
  |- get_annotations - dictionary of content prior to the descriptor entry
  +- get_annotation_lines - lines that provided the annotations
"""

import re
import base64
import hashlib
import datetime

import stem.descriptor
import stem.version
import stem.util.connection
import stem.util.tor_tools

KEYWORD_CHAR    = "a-zA-Z0-9-"
WHITESPACE      = " \t"
KEYWORD_LINE    = re.compile("^([%s]+)[%s]*(.*)$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_START = re.compile("^-----BEGIN ([%s%s]+)-----$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END   = "-----END %s-----"

# relay descriptors must have exactly one of the following
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

def parse_file(descriptor_file, validate = True):
  """
  Iterates over the server descriptors in a file. This can read either relay or
  bridge server descriptors.
  
  Arguments:
    descriptor_file (file) - file with descriptor content
    validate (bool)        - checks the validity of the descriptor's content if
                             True, skips these checks otherwise
  
  Returns:
    iterator for ServerDescriptor instances in the file
  
  Raises:
    ValueError if the contents is malformed and validate is True
    IOError if the file can't be read
  """
  
  # Handler for bridge descriptors
  #
  # Bridge descriptors are scrubbed so their nickname is 'Unnamed' and their
  # ip address is in the 10.x.x.x space (priorly '127.0.0.1'), which is
  # normally reserved for private networks. Bridge descriptors only come from
  # metrics so a file only contains a single descriptor.
  
  first_line = descriptor_file.readline()
  descriptor_file.seek(0)
  
  if first_line.startswith("router Unnamed 10.") or \
    first_line.startswith("router Unnamed 127.0.0.1"):
    yield BridgeDescriptor(descriptor_file.read())
    return
  
  # Handler for relay descriptors
  #
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
  #   - parse as annotations until we get to "router"
  #   - parse as descriptor content until we get to "router-signature" followed
  #     by the end of the signature block
  #   - construct a descriptor and provide it back to the caller
  #
  # Any annotations after the last server descriptor is ignored (never provided
  # to the caller).
  
  while True:
    annotations = _read_until_keyword("router", descriptor_file)
    descriptor_content = _read_until_keyword("router-signature", descriptor_file)
    
    # we've reached the 'router-signature', now include the pgp style block
    block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
    descriptor_content += _read_until_keyword(block_end_prefix, descriptor_file, True)
    
    if descriptor_content:
      # strip newlines from annotations
      annotations = map(str.strip, annotations)
      
      descriptor_text = "".join(descriptor_content)
      descriptor = RelayDescriptor(descriptor_text, validate, annotations)
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

class ServerDescriptor(stem.descriptor.Descriptor):
  """
  Common parent for server descriptors.
  
  Attributes:
    nickname (str)           - relay's nickname (*)
    fingerprint (str)        - fourty hex digits that make up the relay's fingerprint
    address (str)            - IPv4 address of the relay (*)
    or_port (int)            - port used for relaying (*)
    socks_port (int)         - (deprecated) always zero (*)
    dir_port (int)           - port used for descriptor mirroring (*)
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
    eventdns (bool)          - (deprecated) always unset (*)
    
    read_history (str)       - (deprecated) read-history line, always unset
    read_history_end (datetime.datetime) - (deprecated) end of the sampling interval
    read_history_interval (int) - (deprecated) seconds per interval
    read_history_values (list) - (deprecated) bytes read during each interval (*)
    
    write_history (str)      - (deprecated) write-history line, always unset
    write_history_end (datetime.datetime) - (deprecated) end of the sampling interval
    write_history_interval (int) - (deprecated) seconds per interval
    write_history_values (list) - (deprecated) bytes written during each interval (*)
    
    (*) required fields, others are left as None if undefined
  """
  
  def __init__(self, raw_contents, validate = True, annotations = None):
    """
    Server descriptor constructor, created from an individual relay's
    descriptor content (as provided by "GETINFO desc/*", cached descriptors,
    and metrics).
    
    By default this validates the descriptor's content as it's parsed. This
    validation can be disables to either improve performance or be accepting of
    malformed data.
    
    Arguments:
      raw_contents (str) - descriptor content provided by the relay
      validate (bool)    - checks the validity of the descriptor's content if
                           True, skips these checks otherwise
      annotations (list) - lines that appeared prior to the descriptor
    
    Raises:
      ValueError if the contents is malformed and validate is True
    """
    
    stem.descriptor.Descriptor.__init__(self, raw_contents)
    
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
    self.eventdns = True
    
    self.read_history = None
    self.read_history_end = None
    self.read_history_interval = None
    self.read_history_values = []
    
    self.write_history = None
    self.write_history_end = None
    self.write_history_interval = None
    self.write_history_values = []
    
    self._unrecognized_lines = []
    
    self._annotation_lines = annotations if annotations else []
    self._annotation_dict = None # cached breakdown of key/value mappings
    
    # TODO: Until we have a proper ExitPolicy class this is just a list of the
    # exit policy strings...
    
    self.exit_policy = []
    
    # A descriptor contains a series of 'keyword lines' which are simply a
    # keyword followed by an optional value. Lines can also be followed by a
    # signature block.
    #
    # We care about the ordering of 'accept' and 'reject' entries because this
    # influences the resulting exit policy, but for everything else the order
    # does not matter so breaking it into key / value pairs.
    
    entries, first_keyword, last_keyword, self.exit_policy = \
      _get_descriptor_components(raw_contents, validate)
    self._parse(entries, validate)
    if validate: self._check_constraints(entries, first_keyword, last_keyword)
  
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
    
    if self._annotation_dict is None:
      annotation_dict = {}
      
      for line in self._annotation_lines:
        if " " in line:
          key, value = line.split(" ", 1)
          annotation_dict[key] = value
        else: annotation_dict[line] = None
      
      self._annotation_dict = annotation_dict
    
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
  
  def _parse(self, entries, validate):
    """
    Parses a series of 'keyword => (value, pgp block)' mappings and applies
    them as attributes.
    
    Arguments:
      entries (dict)  - descriptor contents to be applied
      validate (bool) - checks the validity of descriptor content if True
    
    Raises:
      ValueError if an error occures in validation
    """
    
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
          elif not stem.util.connection.is_valid_port(router_comp[3], allow_zero = True):
            raise ValueError("Router line's SocksPort is invalid: %s" % router_comp[3])
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
        # We need to be tolerant of negative uptimes to accomidate a past tor
        # bug...
        # 
        # Changes in version 0.1.2.7-alpha - 2007-02-06
        #  - If our system clock jumps back in time, don't publish a negative
        #    uptime in the descriptor. Also, don't let the global rate limiting
        #    buckets go absurdly negative.
        #
        # After parsing all of the attributes we'll double check that negative
        # uptimes only occured prior to this fix.
        
        try:
          self.uptime = int(value)
        except ValueError:
          if not validate: continue
          raise ValueError("Uptime line must have an integer value: %s" % value)
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
      elif keyword == "eventdns":
        self.eventdns = value == "1"
      elif keyword in ("read-history", "write-history"):
        is_read = keyword == "read-history"
        
        if is_read: self.read_history = value
        else: self.write_history = value
        
        value_match = re.match("^(.*) \(([0-9]+) s\) (.*)$", value)
        
        if not value_match:
          if not validate: continue
          raise ValueError("Malformed %s line: %s" % (keyword, line))
        
        end_value, interval_value, history_values = value_match.groups()
        
        try:
          end_datetime = datetime.datetime.strptime(end_value, "%Y-%m-%d %H:%M:%S")
          
          if is_read: self.read_history_end = end_datetime
          else: self.write_history_end = end_datetime
        except ValueError:
          if validate:
            raise ValueError("%s line's time wasn't parseable: %s" % (keyword, line))
        
        if interval_value.isdigit():
          if is_read: self.read_history_interval = int(interval_value)
          else: self.write_history_interval = int(interval_value)
        elif validate:
          raise ValueError("%s line's interval wasn't a number: %s" % (keyword, line))
        
        if history_values != '':
          for sampling in history_values.split(","):
            if sampling.isdigit():
              if is_read: self.read_history_values.append(int(sampling))
              else: self.write_history_values.append(int(sampling))
            else:
              if validate:
                raise ValueError("%s line has non-numeric values: %s" % (keyword, line))
              else: break
      else:
        self._unrecognized_lines.append(line)
    
    # if we have a negative uptime and a tor version that shouldn't exhibit
    # this bug then fail validation
    
    if validate and self.uptime and self.tor_version:
      if self.uptime < 0 and self.tor_version >= stem.version.Version("0.1.2.7"):
        raise ValueError("Descriptor for version '%s' had a negative uptime value: %i" % (self.tor_version, self.uptime))
  
  def _check_constraints(self, entries, first_keyword, last_keyword):
    """
    Does a basic check that the entries conform to this descriptor type's
    constraints.
    
    Arguments:
      entries (dict)      - keyword => (value, pgp key) entries
      first_keyword (str) - keyword of the first line
      last_keyword (str)  - keyword of the last line
    
    Raises:
      ValueError if an issue arises in validation
    """
    
    required_fields = self._required_fields()
    if required_fields:
      for keyword in required_fields:
        if not keyword in entries:
          raise ValueError("Descriptor must have a '%s' entry" % keyword)
    
    single_fields = self._single_fields()
    if single_fields:
      for keyword in self._single_fields():
        if keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in a descriptor" % keyword)
    
    expected_first_keyword = self._first_keyword()
    if expected_first_keyword and not first_keyword == expected_first_keyword:
      raise ValueError("Descriptor must start with a '%s' entry" % first_keyword)
    
    expected_last_keyword = self._last_keyword()
    if expected_last_keyword and not last_keyword == expected_last_keyword:
      raise ValueError("Descriptor must end with a '%s' entry" % last_keyword)
    
    if not self.exit_policy:
      raise ValueError("Descriptor must have at least one 'accept' or 'reject' entry")
  
  # Constraints that the descriptor must meet to be valid. These can be None if
  # not applicable.
  
  def _required_fields(self): return None
  def _single_fields(self): return None
  def _first_keyword(self): return None
  def _last_keyword(self): return None

class RelayDescriptor(ServerDescriptor):
  """
  Server descriptor, as specified in...
  https://gitweb.torproject.org/torspec.git/blob/HEAD:/dir-spec.txt
  
  Attributes:
    onion_key (str)   - key used to encrypt EXTEND cells (*)
    signing_key (str) - relay's long-term identity key (*)
    signature (str)   - signature for this descriptor (*)
    
    (*) required fields, others are left as None if undefined
  """
  
  def __init__(self, raw_contents, validate = True, annotations = None):
    self.onion_key = None
    self.signing_key = None
    self.signature = None
    self._digest = None
    
    ServerDescriptor.__init__(self, raw_contents, validate, annotations)
  
  def is_valid(self):
    """
    Validates that our content matches our signature.
    
    Returns:
      True if our signature matches our content, False otherwise
    """
    
    raise NotImplementedError # TODO: implement
  
  def digest(self):
    """
    Provides the base64 encoded sha1 of our content. This value is part of the
    server descriptor entry for this relay.
    
    Note that network status entries exclude the padding, so you'll need to add
    a '=' to it so they'll match...
    https://en.wikipedia.org/wiki/Base64#Padding
    
    Returns:
      str with the digest value for this server descriptor
    """
    
    if self._digest is None:
      # our digest is calculated from everything except our signature
      raw_content, ending = str(self), "\nrouter-signature\n"
      raw_content = raw_content[:raw_content.find(ending) + len(ending)]
      
      digest_sha1 = hashlib.sha1(raw_content).digest()
      self._digest = base64.b64encode(digest_sha1)
    
    return self._digest
  
  def _parse(self, entries, validate):
    entries = dict(entries) # shallow copy since we're destructive
    
    # handles fields only in server descriptors
    for keyword, values in entries.items():
      value, block_contents = values[0]
      line = "%s %s" % (keyword, value)
      
      if keyword == "onion-key":
        if validate and not block_contents:
          raise ValueError("Onion key line must be followed by a public key: %s" % line)
        
        self.onion_key = block_contents
        del entries["onion-key"]
      elif keyword == "signing-key":
        if validate and not block_contents:
          raise ValueError("Signing key line must be followed by a public key: %s" % line)
        
        self.signing_key = block_contents
        del entries["signing-key"]
      elif keyword == "router-signature":
        if validate and not block_contents:
          raise ValueError("Router signature line must be followed by a signature block: %s" % line)
        
        self.signature = block_contents
        del entries["router-signature"]
    
    ServerDescriptor._parse(self, entries, validate)
  
  def _required_fields(self):
    return REQUIRED_FIELDS
  
  def _single_fields(self):
    return REQUIRED_FIELDS + SINGLE_FIELDS
  
  def _first_keyword(self):
    return "router"
  
  def _last_keyword(self):
    return "router-signature"

class BridgeDescriptor(ServerDescriptor):
  """
  Bridge descriptor, as specified in...
  https://metrics.torproject.org/formats.html#bridgedesc
  
  Attributes:
    address_alt (list) - alternative for our address/or_port attributes, each
                         entry is a tuple of the form...
                         (address (str), port (int), is_ipv6 (bool))
  """
  
  def __init__(self, raw_contents, validate = True, annotations = None):
    self.address_alt = []
    self._scrubbing_issues = None
    ServerDescriptor.__init__(self, raw_contents, validate, annotations)
  
  def _parse(self, entries, validate):
    entries = dict(entries)
    
    # handles fields only in bridge descriptors
    for keyword, values in entries.items():
      if keyword == "or-address":
        or_address_entries = [value for (value, _) in values]
        
        for entry in or_address_entries:
          line = "%s %s" % (keyword, entry)
          
          if not ":" in entry:
            if not validate: continue
            else: raise ValueError("or-address line missing a colon: %s" % line)
          
          div = entry.rfind(":")
          address, ports = entry[:div], entry[div+1:]
          is_ipv6 = address.startswith("[") and address.endswith("]")
          if is_ipv6: address = address[1:-1] # remove brackets
          
          if not ((not is_ipv6 and stem.util.connection.is_valid_ip_address(address)) or
                 (is_ipv6 and stem.util.connection.is_valid_ipv6_address(address))):
            if not validate: continue
            else: raise ValueError("or-address line has a malformed address: %s" % line)
          
          for port in ports.split(","):
            if not stem.util.connection.is_valid_port(port):
              if not validate: break
              else: raise ValueError("or-address line has malformed ports: %s" % line)
            
            self.address_alt.append((address, int(port), is_ipv6))
        
        del entries["or-address"]
    
    ServerDescriptor._parse(self, entries, validate)
  
  def is_scrubbed(self):
    """
    Checks if we've been properly scrubbed in accordance with the bridge
    descriptor specification. Validation is a moving target so this may not
    be fully up to date.
    
    Returns:
      True if we're scrubbed, False otherwise
    """
    
    return self.get_scrubbing_issues() == []
  
  def get_scrubbing_issues(self):
    """
    Provides issues with our scrubbing.
    
    Returns:
      list of strings which describe issues we have with our scrubbing, this
      list is empty if we're properly scrubbed
    """
    
    if self._scrubbing_issues == None:
      issues = []
      if self.nickname != "Unnamed":
        issues.append("Router line's nickname should be scrubbed to be 'Unnamed': %s" % self.nickname)
      elif not self.address.startswith("10."):
        issues.append("Router line's address should be scrubbed to be '10.x.x.x': %s" % self.address)
      elif self.contact and self.contact != "somebody":
        issues.append("Contact line should be scrubbed to be 'somebody', but instead had '%s'" % self.contact)
      
      for address, _, is_ipv6 in self.address_alt:
        if not is_ipv6 and not address.startswith("10."):
          issues.append("or-address line's address should be scrubbed to be '10.x.x.x': %s" % address)
        elif is_ipv6 and not address.startswith("fd9f:2e19:3bcf::"):
          # TODO: this check isn't quite right because we aren't checking that
          # the next grouping of hex digits contains 1-2 digits
          issues.append("or-address line's address should be scrubbed to be 'fd9f:2e19:3bcf::xx:xxxx': %s" % address)
      
      for line in self.get_unrecognized_lines():
        if line.startswith("onion-key "):
          issues.append("Bridge descriptors should have their onion-key scrubbed: %s" % line)
        elif line.startswith("signing-key "):
          issues.append("Bridge descriptors should have their signing-key scrubbed: %s" % line)
        elif line.startswith("router-signature "):
          issues.append("Bridge descriptors should have their signature scrubbed: %s" % line)
      
      self._scrubbing_issues = issues
    
    return self._scrubbing_issues
  
  def _required_fields(self):
    # bridge required fields are the same as a relay descriptor, minus items
    # excluded according to the format page
    
    excluded_fields = (
      "onion-key",
      "signing-key",
      "router-signature",
    )
    
    return filter(lambda e: not e in excluded_fields, REQUIRED_FIELDS)
  
  def _single_fields(self):
    return self._required_fields() + SINGLE_FIELDS
  
  def _first_keyword(self):
    return "router"

def _get_descriptor_components(raw_contents, validate):
  """
  Initial breakup of the server descriptor contents to make parsing easier.
  
  A descriptor contains a series of 'keyword lines' which are simply a keyword
  followed by an optional value. Lines can also be followed by a signature
  block.
  
  We care about the ordering of 'accept' and 'reject' entries because this
  influences the resulting exit policy, but for everything else the order does
  not matter so breaking it into key / value pairs.
  
  Arguments:
    raw_contents (str) - descriptor content provided by the relay
    validate (bool)    - checks the validity of the descriptor's content if
                         True, skips these checks otherwise
  
  Returns:
    tuple with the following attributes...
      entries (dict)      - keyword => (value, pgp key) entries
      first_keyword (str) - keyword of the first line
      last_keyword (str)  - keyword of the last line
      exit_policy (list)  - lines containing the exit policy
  """
  
  entries = {}
  first_keyword = None
  last_keyword = None
  exit_policy = []
  remaining_lines = raw_contents.split("\n")
  
  while remaining_lines:
    line = remaining_lines.pop(0)
    
    # last line can be empty
    if not line and not remaining_lines: continue
    
    # Some lines have an 'opt ' for backward compatability. They should be
    # ignored. This prefix is being removed in...
    # https://trac.torproject.org/projects/tor/ticket/5124
    
    if line.startswith("opt "): line = line[4:]
    
    line_match = KEYWORD_LINE.match(line)
    
    if not line_match:
      if not validate: continue
      raise ValueError("Line contains invalid characters: %s" % line)
    
    keyword, value = line_match.groups()
    
    if not first_keyword: first_keyword = keyword
    last_keyword = keyword
    
    try:
      block_contents = _get_pseudo_pgp_block(remaining_lines)
    except ValueError, exc:
      if not validate: continue
      raise exc
    
    if keyword in ("accept", "reject"):
      exit_policy.append("%s %s" % (keyword, value))
    elif keyword in entries:
      entries[keyword].append((value, block_contents))
    else:
      entries[keyword] = [(value, block_contents)]
  
  return entries, first_keyword, last_keyword, exit_policy

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

