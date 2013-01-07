"""
Parsing for Tor network status documents. This supports both the v2 and v3
dir-spec. Documents can be obtained from a few sources...

* the 'cached-consensus' file in tor's data directory
* tor metrics, at https://metrics.torproject.org/data.html
* directory authorities and mirrors via their DirPort

... and contain the following sections...

* document header
* list of :class:`stem.descriptor.networkstatus.DirectoryAuthority`
* list of :class:`stem.descriptor.router_status_entry.RouterStatusEntry`
* document footer

Of these, the router status entry section can be quite large (on the order of
hundreds of kilobytes). As such we provide a couple of methods for reading
network status documents...

* :class:`stem.descriptor.networkstatus.NetworkStatusDocumentV3` constructor

If read time and memory aren't a concern then you can simply use the document
constructor. Router entries are assigned to its 'routers' attribute...

::

  from stem.descriptor.networkstatus import NetworkStatusDocumentV3
  
  # Reads the full consensus into memory twice (both for the parsed and
  # unparsed contents).
  
  consensus_file = open('.tor/cached-consensus', 'r')
  consensus = NetworkStatusDocumentV3(consensus_file.read())
  consensus_file.close()
  
  for router in consensus.routers:
    print router.nickname

* :func:`stem.descriptor.networkstatus.parse_file`

Alternatively, the :func:`~stem.descriptor.networkstatus.parse_file` function
provides an iterator for a document's routers. Those routers refer to a 'thin'
document, which doesn't have a 'routers' attribute. This allows for lower
memory usage and upfront runtime.

::

  from stem.descriptor.networkstatus import parse_file
  
  with open('.tor/cached-consensus', 'r') as consensus_file:
    # Processes the routers as we read them in. The routers refer to a document
    # with an unset 'routers' attribute.
    
    for router in parse_file(consensus_file):
      print router.nickname

**Module Overview:**

::

  parse_file - parses a network status file, providing an iterator for its routers
  
  NetworkStatusDocument - Network status document
    |- NetworkStatusDocumentV2 - Version 2 network status document
    +- NetworkStatusDocumentV3 - Version 3 network status document
  
  DocumentSignature - Signature of a document by a directory authority
  DirectoryAuthority - Directory authority as defined in a v3 network status document
"""

import datetime
import StringIO

import stem.descriptor
import stem.descriptor.router_status_entry
import stem.util.tor_tools
import stem.version

# Version 2 network status document fields, tuples of the form...
# (keyword, is_mandatory)

NETWORK_STATUS_V2_FIELDS = (
  ("network-status-version", True),
  ("dir-source", True),
  ("fingerprint", True),
  ("contact", True),
  ("dir-signing-key", True),
  ("client-versions", False),
  ("server-versions", False),
  ("published", True),
  ("dir-options", False),
  ("directory-signature", True),
)

# Network status document are either a 'vote' or 'consensus', with different
# mandatory fields for each. Both though require that their fields appear in a
# specific order. This is an ordered listing of the following...
#
# (field, in_votes, in_consensus, is_mandatory)

HEADER_STATUS_DOCUMENT_FIELDS = (
  ("network-status-version", True, True, True),
  ("vote-status", True, True, True),
  ("consensus-methods", True, False, False),
  ("consensus-method", False, True, False),
  ("published", True, False, True),
  ("valid-after", True, True, True),
  ("fresh-until", True, True, True),
  ("valid-until", True, True, True),
  ("voting-delay", True, True, True),
  ("client-versions", True, True, False),
  ("server-versions", True, True, False),
  ("known-flags", True, True, True),
  ("params", True, True, False),
)

FOOTER_STATUS_DOCUMENT_FIELDS = (
  ("directory-footer", True, True, True),
  ("bandwidth-weights", False, True, False),
  ("directory-signature", True, True, True),
)

HEADER_FIELDS = [attr[0] for attr in HEADER_STATUS_DOCUMENT_FIELDS]
FOOTER_FIELDS = [attr[0] for attr in FOOTER_STATUS_DOCUMENT_FIELDS]

AUTH_START = "dir-source"
ROUTERS_START = "r"
FOOTER_START = "directory-footer"
V2_FOOTER_START = "directory-signature"

DEFAULT_PARAMS = {
  "bwweightscale": 10000,
  "cbtdisabled": 0,
  "cbtnummodes": 3,
  "cbtrecentcount": 20,
  "cbtmaxtimeouts": 18,
  "cbtmincircs": 100,
  "cbtquantile": 80,
  "cbtclosequantile": 95,
  "cbttestfreq": 60,
  "cbtmintimeout": 2000,
  "cbtinitialtimeout": 60000,
}

# KeyCertificate fields, tuple is of the form...
# (keyword, is_mandatory)

KEY_CERTIFICATE_PARAMS = (
  ('dir-key-certificate-version', True),
  ('dir-address', False),
  ('fingerprint', True),
  ('dir-identity-key', True),
  ('dir-key-published', True),
  ('dir-key-expires', True),
  ('dir-signing-key', True),
  ('dir-key-crosscert', False),
  ('dir-key-certification', True),
)

BANDWIDTH_WEIGHT_ENTRIES = (
  "Wbd", "Wbe", "Wbg", "Wbm",
  "Wdb",
  "Web", "Wed", "Wee", "Weg", "Wem",
  "Wgb", "Wgd", "Wgg", "Wgm",
  "Wmb", "Wmd", "Wme", "Wmg", "Wmm",
)


def parse_file(document_file, validate = True, is_microdescriptor = False, document_version = 3):
  """
  Parses a network status and iterates over the RouterStatusEntry in it. The
  document that these instances reference have an empty 'routers' attribute to
  allow for limited memory usage.
  
  :param file document_file: file with network status document content
  :param bool validate: checks the validity of the document's contents if
    **True**, skips these checks otherwise
  :param bool is_microdescriptor: **True** if this is for a microdescriptor
    consensus, **False** otherwise
  :param int document_version: network status document version
  
  :returns: :class:`stem.descriptor.networkstatus.NetworkStatusDocument` object
  
  :raises:
    * **ValueError** if the document_version is unrecognized or the contents is
      malformed and validate is **True**
    * **IOError** if the file can't be read
  """
  
  # getting the document without the routers section
  
  header = stem.descriptor._read_until_keywords((ROUTERS_START, FOOTER_START, V2_FOOTER_START), document_file)
  
  routers_start = document_file.tell()
  stem.descriptor._read_until_keywords((FOOTER_START, V2_FOOTER_START), document_file, skip = True)
  routers_end = document_file.tell()
  
  footer = document_file.readlines()
  document_content = "".join(header + footer)
  
  if document_version == 2:
    document_type = NetworkStatusDocumentV2
    router_type = stem.descriptor.router_status_entry.RouterStatusEntryV3
  elif document_version == 3:
    document_type = NetworkStatusDocumentV3
    
    if not is_microdescriptor:
      router_type = stem.descriptor.router_status_entry.RouterStatusEntryV3
    else:
      router_type = stem.descriptor.router_status_entry.RouterStatusEntryMicroV3
  else:
    raise ValueError("Document version %i isn't recognized (only able to parse v2 or v3)" % document_version)
  
  desc_iterator = stem.descriptor.router_status_entry.parse_file(
    document_file,
    validate,
    entry_class = router_type,
    entry_keyword = ROUTERS_START,
    start_position = routers_start,
    end_position = routers_end,
    extra_args = (document_type(document_content, validate),),
  )
  
  for desc in desc_iterator:
    yield desc


class NetworkStatusDocument(stem.descriptor.Descriptor):
  """
  Common parent for network status documents.
  """
  
  def __init__(self, raw_content):
    super(NetworkStatusDocument, self).__init__(raw_content)
    self._unrecognized_lines = []
  
  def get_unrecognized_lines(self):
    return list(self._unrecognized_lines)


class NetworkStatusDocumentV2(NetworkStatusDocument):
  """
  Version 2 network status document. These have been deprecated and are no
  longer generated by Tor.
  
  :var tuple routers: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV2`
    contained in the document
  
  :var int version: **\*** document version
  
  :var str hostname: **\*** hostname of the authority
  :var str address: **\*** authority's IP address
  :var int dir_port: **\*** authority's DirPort
  :var str fingerprint: **\*** authority's fingerprint
  :var str contact: **\*** authority's contact information
  :var str signing_key: **\*** authority's public signing key
  
  :var list client_versions: list of recommended client tor version strings
  :var list server_versions: list of recommended server tor version strings
  :var datetime published: **\*** time when the document was published
  :var list options: **\*** list of things that this authority decides
  
  :var str signing_authority: **\*** name of the authority signing the document
  :var str signature: **\*** authority's signature for the document
  
  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined
  """
  
  def __init__(self, raw_content, validate = True):
    super(NetworkStatusDocumentV2, self).__init__(raw_content)
    
    self.version = None
    self.hostname = None
    self.address = None
    self.dir_port = None
    self.fingerprint = None
    self.contact = None
    self.signing_key = None
    
    self.client_versions = []
    self.server_versions = []
    self.published = None
    self.options = []
    
    self.signing_authority = None
    self.signatures = None
    
    # Splitting the document from the routers. Unlike v3 documents we're not
    # bending over backwards on the validation by checking the field order or
    # that header/footer attributes aren't in the wrong section. This is a
    # deprecated descriptor type - patches welcome if you want those checks.
    
    document_file = StringIO.StringIO(raw_content)
    document_content = "".join(stem.descriptor._read_until_keywords((ROUTERS_START, V2_FOOTER_START), document_file))
    
    self.routers = tuple(stem.descriptor.router_status_entry.parse_file(
      document_file,
      validate,
      entry_class = stem.descriptor.router_status_entry.RouterStatusEntryV2,
      entry_keyword = ROUTERS_START,
      section_end_keywords = (V2_FOOTER_START,),
      extra_args = (self,),
    ))
    
    document_content += "\n" + document_file.read()
    
    entries = stem.descriptor._get_descriptor_components(document_content, validate)
    
    if validate:
      self._check_constraints(entries)
    
    self._parse(entries, validate)
  
  def _parse(self, entries, validate):
    for keyword, values in entries.items():
      value, block_contents = values[0]
      
      line = "%s %s" % (keyword, value)  # original line
      
      if block_contents:
        line += "\n%s" % block_contents
      
      if keyword == "network-status-version":
        if not value.isdigit():
          if not validate:
            continue
          
          raise ValueError("Network status document has a non-numeric version: %s" % line)
        
        self.version = int(value)
        
        if validate and self.version != 2:
          raise ValueError("Expected a version 2 network status document, got version '%s' instead" % self.version)
      elif keyword == "dir-source":
        dir_source_comp = value.split()
        
        if len(dir_source_comp) < 3:
          if not validate:
            continue
          
          raise ValueError("The 'dir-source' line of a v2 network status document must have three values: %s" % line)
        
        if validate:
          if not dir_source_comp[0]:
            # https://trac.torproject.org/7055
            raise ValueError("Authority's hostname can't be blank: %s" % line)
          elif not stem.util.connection.is_valid_ip_address(dir_source_comp[1]):
            raise ValueError("Authority's address isn't a valid IPv4 address: %s" % dir_source_comp[1])
          elif not stem.util.connection.is_valid_port(dir_source_comp[2], allow_zero = True):
            raise ValueError("Authority's DirPort is invalid: %s" % dir_source_comp[2])
        elif not dir_source_comp[2].isdigit():
          continue
        
        self.hostname = dir_source_comp[0]
        self.address = dir_source_comp[1]
        self.dir_port = None if dir_source_comp[2] == '0' else int(dir_source_comp[2])
      elif keyword == "fingerprint":
        if validate and not stem.util.tor_tools.is_valid_fingerprint(value):
          raise ValueError("Authority's fingerprint in a v2 network status document is malformed: %s" % line)
        
        self.fingerprint = value
      elif keyword == "contact":
        self.contact = value
      elif keyword == "dir-signing-key":
        self.signing_key = block_contents
      elif keyword in ("client-versions", "server-versions"):
        # v2 documents existed while there were tor versions using the 'old'
        # style, hence we aren't attempting to parse them
        
        for version_str in value.split(","):
          if keyword == 'client-versions':
            self.client_versions.append(version_str)
          elif keyword == 'server-versions':
            self.server_versions.append(version_str)
      elif keyword == "published":
        try:
          self.published = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
          if validate:
            raise ValueError("Version 2 network status document's 'published' time wasn't parsable: %s" % value)
      elif keyword == "dir-options":
        self.options = value.split()
      elif keyword == "directory-signature":
        self.signing_authority = value
        self.signature = block_contents
      else:
        self._unrecognized_lines.append(line)
    
    # 'client-versions' and 'server-versions' are only required if "Versions"
    # is among the options
    
    if validate and "Versions" in self.options:
      if not ('client-versions' in entries and 'server-versions' in entries):
        raise ValueError("Version 2 network status documents must have a 'client-versions' and 'server-versions' when 'Versions' is listed among its dir-options:\n%s" % str(self))
  
  def _check_constraints(self, entries):
    required_fields = [field for (field, is_mandatory) in NETWORK_STATUS_V2_FIELDS if is_mandatory]
    for keyword in required_fields:
      if not keyword in entries:
        raise ValueError("Network status document (v2) must have a '%s' line:\n%s" % (keyword, str(self)))
    
    # all recognized fields can only appear once
    single_fields = [field for (field, _) in NETWORK_STATUS_V2_FIELDS]
    for keyword in single_fields:
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("Network status document (v2) can only have a single '%s' line, got %i:\n%s" % (keyword, len(entries[keyword]), str(self)))
    
    if 'network-status-version' != entries.keys()[0]:
      raise ValueError("Network status document (v2) are expected to start with a 'network-status-version' line:\n%s" % str(self))


class NetworkStatusDocumentV3(NetworkStatusDocument):
  """
  Version 3 network status document. This could be either a vote or consensus.
  
  :var tuple routers: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`
    contained in the document
  
  :var int version: **\*** document version
  :var str version_flavor: **\*** flavor associated with the document (such as 'microdesc')
  :var bool is_consensus: **\*** **True** if the document is a consensus
  :var bool is_vote: **\*** **True** if the document is a vote
  :var bool is_microdescriptor: **\*** **True** if this is a microdescriptor
    flavored document, **False** otherwise
  :var datetime valid_after: **\*** time when the consensus became valid
  :var datetime fresh_until: **\*** time when the next consensus should be produced
  :var datetime valid_until: **\*** time when this consensus becomes obsolete
  :var int vote_delay: **\*** number of seconds allowed for collecting votes
    from all authorities
  :var int dist_delay: **\*** number of seconds allowed for collecting
    signatures from all authorities
  :var list client_versions: list of recommended client tor versions
  :var list server_versions: list of recommended server tor versions
  :var list known_flags: **\*** list of known router flags
  :var list params: **\*** dict of parameter(**str**) => value(**int**) mappings
  :var list directory_authorities: **\*** list of :class:`~stem.descriptor.networkstatus.DirectoryAuthority`
    objects that have generated this document
  :var list signatures: **\*** :class:`~stem.descriptor.networkstatus.DocumentSignature`
    of the authorities that have signed the document
  
  **Consensus Attributes:**
  
  :var int consensus_method: method version used to generate this consensus
  :var dict bandwidth_weights: dict of weight(str) => value(int) mappings
  
  **Vote Attributes:**
  
  :var list consensus_methods: list of ints for the supported method versions
  :var datetime published: time when the document was published
  
  **\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as None if undefined
  """
  
  def __init__(self, raw_content, validate = True, default_params = True):
    """
    Parse a v3 network status document.
    
    :param str raw_content: raw network status document data
    :param bool validate: **True** if the document is to be validated, **False** otherwise
    :param bool default_params: includes defaults in our params dict, otherwise
      it just contains values from the document
    
    :raises: **ValueError** if the document is invalid
    """
    
    super(NetworkStatusDocumentV3, self).__init__(raw_content)
    document_file = StringIO.StringIO(raw_content)
    
    self._header = _DocumentHeader(document_file, validate, default_params)
    
    # merge header attributes into us
    for attr, value in vars(self._header).items():
      if attr != "_unrecognized_lines":
        setattr(self, attr, value)
      else:
        self._unrecognized_lines += value
    
    self.directory_authorities = tuple(stem.descriptor.router_status_entry.parse_file(
      document_file,
      validate,
      entry_class = DirectoryAuthority,
      entry_keyword = AUTH_START,
      section_end_keywords = (ROUTERS_START, FOOTER_START),
      extra_args = (self._header.is_vote,),
    ))
    
    if not self._header.is_microdescriptor:
      router_type = stem.descriptor.router_status_entry.RouterStatusEntryV3
    else:
      router_type = stem.descriptor.router_status_entry.RouterStatusEntryMicroV3
    
    self.routers = tuple(stem.descriptor.router_status_entry.parse_file(
      document_file,
      validate,
      entry_class = router_type,
      entry_keyword = ROUTERS_START,
      section_end_keywords = (FOOTER_START,),
      extra_args = (self,),
    ))
    
    self._footer = _DocumentFooter(document_file, validate, self._header)
    
    # merge header attributes into us
    for attr, value in vars(self._footer).items():
      if attr != "_unrecognized_lines":
        setattr(self, attr, value)
      else:
        self._unrecognized_lines += value
  
  def meets_consensus_method(self, method):
    """
    Checks if we meet the given consensus-method. This works for both votes and
    consensuses, checking our 'consensus-method' and 'consensus-methods'
    entries.
    
    :param int method: consensus-method to check for
    
    :returns: **True** if we meet the given consensus-method, and **False** otherwise
    """
    
    return self._header.meets_consensus_method(method)
  
  def __cmp__(self, other):
    if not isinstance(other, NetworkStatusDocumentV3):
      return 1
    
    return str(self) > str(other)


class _DocumentHeader(object):
  def __init__(self, document_file, validate, default_params):
    self.version = None
    self.version_flavor = None
    self.is_consensus = True
    self.is_vote = False
    self.is_microdescriptor = False
    self.consensus_methods = []
    self.published = None
    self.consensus_method = None
    self.valid_after = None
    self.fresh_until = None
    self.valid_until = None
    self.vote_delay = None
    self.dist_delay = None
    self.client_versions = []
    self.server_versions = []
    self.known_flags = []
    self.params = dict(DEFAULT_PARAMS) if default_params else {}
    
    self._unrecognized_lines = []
    
    content = "".join(stem.descriptor._read_until_keywords((AUTH_START, ROUTERS_START, FOOTER_START), document_file))
    entries = stem.descriptor._get_descriptor_components(content, validate)
    self._parse(entries, validate)
    
    # doing this validation afterward so we know our 'is_consensus' and
    # 'is_vote' attributes
    
    if validate:
      _check_for_missing_and_disallowed_fields(self, entries, HEADER_STATUS_DOCUMENT_FIELDS)
      _check_for_misordered_fields(entries, HEADER_FIELDS)
  
  def meets_consensus_method(self, method):
    return bool(self.consensus_method >= method or filter(lambda x: x >= method, self.consensus_methods))
  
  def _parse(self, entries, validate):
    for keyword, values in entries.items():
      value, _ = values[0]
      line = "%s %s" % (keyword, value)
      
      # all known header fields can only appear once except
      if validate and len(values) > 1 and keyword in HEADER_FIELDS:
        raise ValueError("Network status documents can only have a single '%s' line, got %i" % (keyword, len(values)))
      
      if keyword == 'network-status-version':
        # "network-status-version" version
        
        if ' ' in value:
          version, flavor = value.split(' ', 1)
        else:
          version, flavor = value, None
        
        if not version.isdigit():
          if not validate:
            continue
          
          raise ValueError("Network status document has a non-numeric version: %s" % line)
        
        self.version = int(version)
        self.version_flavor = flavor
        self.is_microdescriptor = flavor == 'microdesc'
        
        if validate and self.version != 3:
          raise ValueError("Expected a version 3 network status document, got version '%s' instead" % self.version)
      elif keyword == 'vote-status':
        # "vote-status" type
        #
        # The consensus-method and consensus-methods fields are optional since
        # they weren't included in version 1. Setting a default now that we
        # know if we're a vote or not.
        
        if value == 'consensus':
          self.is_consensus, self.is_vote = True, False
          self.consensus_method = 1
        elif value == 'vote':
          self.is_consensus, self.is_vote = False, True
          self.consensus_methods = [1]
        elif validate:
          raise ValueError("A network status document's vote-status line can only be 'consensus' or 'vote', got '%s' instead" % value)
      elif keyword == 'consensus-methods':
        # "consensus-methods" IntegerList
        
        consensus_methods = []
        for entry in value.split(" "):
          if entry.isdigit():
            consensus_methods.append(int(entry))
          elif validate:
            raise ValueError("A network status document's consensus-methods must be a list of integer values, but was '%s'" % value)
        
        self.consensus_methods = consensus_methods
        
        if validate and not (1 in self.consensus_methods):
          raise ValueError("Network status votes must include consensus-method version 1")
      elif keyword == 'consensus-method':
        # "consensus-method" Integer
        
        if value.isdigit():
          self.consensus_method = int(value)
        elif validate:
          raise ValueError("A network status document's consensus-method must be an integer, but was '%s'" % value)
      elif keyword in ('published', 'valid-after', 'fresh-until', 'valid-until'):
        try:
          date_value = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
          
          if keyword == 'published':
            self.published = date_value
          elif keyword == 'valid-after':
            self.valid_after = date_value
          elif keyword == 'fresh-until':
            self.fresh_until = date_value
          elif keyword == 'valid-until':
            self.valid_until = date_value
        except ValueError:
          if validate:
            raise ValueError("Network status document's '%s' time wasn't parsable: %s" % (keyword, value))
      elif keyword == "voting-delay":
        # "voting-delay" VoteSeconds DistSeconds
        
        value_comp = value.split(' ')
        
        if len(value_comp) == 2 and value_comp[0].isdigit() and value_comp[1].isdigit():
          self.vote_delay = int(value_comp[0])
          self.dist_delay = int(value_comp[1])
        elif validate:
          raise ValueError("A network status document's 'voting-delay' line must be a pair of integer values, but was '%s'" % value)
      elif keyword in ("client-versions", "server-versions"):
        for entry in value.split(","):
          try:
            version_value = stem.version.Version(entry)
            
            if keyword == 'client-versions':
              self.client_versions.append(version_value)
            elif keyword == 'server-versions':
              self.server_versions.append(version_value)
          except ValueError:
            if validate:
              raise ValueError("Network status document's '%s' line had '%s', which isn't a parsable tor version: %s" % (keyword, entry, line))
      elif keyword == "known-flags":
        # "known-flags" FlagList
        
        # simply fetches the entries, excluding empty strings
        self.known_flags = [entry for entry in value.split(" ") if entry]
      elif keyword == "params":
        # "params" [Parameters]
        # Parameter ::= Keyword '=' Int32
        # Int32 ::= A decimal integer between -2147483648 and 2147483647.
        # Parameters ::= Parameter | Parameters SP Parameter
        
        # should only appear in consensus-method 7 or later
        
        if validate and not self.meets_consensus_method(7):
          raise ValueError("A network status document's 'params' line should only appear in consensus-method 7 or later")
        
        # skip if this is a blank line
        
        if value == "":
          continue
        
        self.params.update(_parse_int_mappings(keyword, value, validate))
        
        if validate:
          self._check_params_constraints()
      else:
        self._unrecognized_lines.append(line)
  
  def _check_params_constraints(self):
    """
    Checks that the params we know about are within their documented ranges.
    """
    
    for key, value in self.params.items():
      # all parameters are constrained to int32 range
      minimum, maximum = -2147483648, 2147483647
      
      if key == "circwindow":
        minimum, maximum = 100, 1000
      elif key == "CircuitPriorityHalflifeMsec":
        minimum = -1
      elif key in ("perconnbwrate", "perconnbwburst"):
        minimum = 1
      elif key == "refuseunknownexits":
        minimum, maximum = 0, 1
      elif key == "bwweightscale":
        minimum = 1
      elif key == "cbtdisabled":
        minimum, maximum = 0, 1
      elif key == "cbtnummodes":
        minimum, maximum = 1, 20
      elif key == "cbtrecentcount":
        minimum, maximum = 3, 1000
      elif key == "cbtmaxtimeouts":
        minimum, maximum = 3, 10000
      elif key == "cbtmincircs":
        minimum, maximum = 1, 10000
      elif key == "cbtquantile":
        minimum, maximum = 10, 99
      elif key == "cbtclosequantile":
        minimum, maximum = self.params.get("cbtquantile", minimum), 99
      elif key == "cbttestfreq":
        minimum = 1
      elif key == "cbtmintimeout":
        minimum = 500
      elif key == "cbtinitialtimeout":
        minimum = self.params.get("cbtmintimeout", minimum)
      
      if value < minimum or value > maximum:
        raise ValueError("'%s' value on the params line must be in the range of %i - %i, was %i" % (key, minimum, maximum, value))


class _DocumentFooter(object):
  def __init__(self, document_file, validate, header):
    self.signatures = []
    self.bandwidth_weights = {}
    self._unrecognized_lines = []
    
    content = document_file.read()
    if validate and content and not header.meets_consensus_method(9):
      raise ValueError("Network status document's footer should only appear in consensus-method 9 or later")
    elif not content and not header.meets_consensus_method(9):
      return  # footer is optional and there's nothing to parse
    
    entries = stem.descriptor._get_descriptor_components(content, validate)
    self._parse(entries, validate, header)
    
    if validate:
      _check_for_missing_and_disallowed_fields(header, entries, FOOTER_STATUS_DOCUMENT_FIELDS)
      _check_for_misordered_fields(entries, FOOTER_FIELDS)
  
  def _parse(self, entries, validate, header):
    for keyword, values in entries.items():
      value, block_contents = values[0]
      line = "%s %s" % (keyword, value)
      
      # all known footer fields can only appear once except...
      # * 'directory-signature' in a consensus
      
      if validate and len(values) > 1 and keyword in FOOTER_FIELDS:
        if not (keyword == 'directory-signature' and header.is_consensus):
          raise ValueError("Network status documents can only have a single '%s' line, got %i" % (keyword, len(values)))
      
      if keyword == "directory-footer":
        # nothing to parse, simply checking that we don't have a value
        
        if validate and value:
          raise ValueError("A network status document's 'directory-footer' line shouldn't have any content, got '%s'" % line)
      elif keyword == "bandwidth-weights":
        self.bandwidth_weights = _parse_int_mappings(keyword, value, validate)
        
        if validate:
          weight_keys = tuple(sorted(self.bandwidth_weights.keys()))
          
          if weight_keys != BANDWIDTH_WEIGHT_ENTRIES:
            expected_label = ', '.join(BANDWIDTH_WEIGHT_ENTRIES)
            actual_label = ', '.join(weight_keys)
            
            raise ValueError("A network status document's 'bandwidth-weights' entries should be '%s', got '%s'" % (expected_label, actual_label))
      elif keyword == "directory-signature":
        for sig_value, block_contents in values:
          if not sig_value.count(" ") in (1, 2) or not block_contents:
            if not validate:
              continue
            
            raise ValueError("Authority signatures in a network status document are expected to be of the form 'directory-signature [METHOD] FINGERPRINT KEY_DIGEST\\nSIGNATURE', got:\n%s\n%s" % (sig_value, block_contents))
          
          if sig_value.count(" ") == 1:
            method = 'sha1'  # default if none was provided
            fingerprint, key_digest = sig_value.split(" ", 1)
          else:
            method, fingerprint, key_digest = sig_value.split(" ", 2)
          
          self.signatures.append(DocumentSignature(method, fingerprint, key_digest, block_contents, validate))


def _check_for_missing_and_disallowed_fields(header, entries, fields):
  """
  Checks that we have mandatory fields for our type, and that we don't have
  any fields exclusive to the other (ie, no vote-only fields appear in a
  consensus or vice versa).
  
  :param _DocumentHeader header: document header
  :param dict entries: ordered keyword/value mappings of the header or footer
  :param list fields: expected field attributes (either
    **HEADER_STATUS_DOCUMENT_FIELDS** or **FOOTER_STATUS_DOCUMENT_FIELDS**)
  
  :raises: **ValueError** if we're missing mandatory fields or have fields we shouldn't
  """
  
  missing_fields, disallowed_fields = [], []
  
  for field, in_votes, in_consensus, mandatory in fields:
    if mandatory and ((header.is_consensus and in_consensus) or (header.is_vote and in_votes)):
      # mandatory field, check that we have it
      if not field in entries.keys():
        missing_fields.append(field)
    elif (header.is_consensus and not in_consensus) or (header.is_vote and not in_votes):
      # field we shouldn't have, check that we don't
      if field in entries.keys():
        disallowed_fields.append(field)
  
  if missing_fields:
    raise ValueError("Network status document is missing mandatory field: %s" % ', '.join(missing_fields))
  
  if disallowed_fields:
    raise ValueError("Network status document has fields that shouldn't appear in this document type or version: %s" % ', '.join(disallowed_fields))


def _check_for_misordered_fields(entries, expected):
  """
  To be valid a network status document's fiends need to appear in a specific
  order. Checks that known fields appear in that order (unrecognized fields
  are ignored).
  
  :param dict entries: ordered keyword/value mappings of the header or footer
  :param list expected: ordered list of expected fields (either
    **HEADER_FIELDS** or **FOOTER_FIELDS**)
  
  :raises: **ValueError** if entries aren't properly ordered
  """
  
  # Earlier validation has ensured that our fields either belong to our
  # document type or are unknown. Remove the unknown fields since they
  # reflect a spec change and can appear anywhere in the document.
  
  actual = filter(lambda field: field in expected, entries.keys())
  
  # Narrow the expected to just what we have. If the lists then match then the
  # order's valid.
  
  expected = filter(lambda field: field in actual, expected)
  
  if actual != expected:
    actual_label = ', '.join(actual)
    expected_label = ', '.join(expected)
    raise ValueError("The fields in a section of the document are misordered. It should be '%s' but was '%s'" % (actual_label, expected_label))


def _parse_int_mappings(keyword, value, validate):
  # Parse a series of 'key=value' entries, checking the following:
  # - values are integers
  # - keys are sorted in lexical order
  
  results, seen_keys = {}, []
  for entry in value.split(" "):
    try:
      if not '=' in entry:
        raise ValueError("must only have 'key=value' entries")
      
      entry_key, entry_value = entry.split("=", 1)
      
      try:
        # the int() function accepts things like '+123', but we don't want to
        if entry_value.startswith('+'):
          raise ValueError()
        
        entry_value = int(entry_value)
      except ValueError:
        raise ValueError("'%s' is a non-numeric value" % entry_value)
      
      if validate:
        # parameters should be in ascending order by their key
        for prior_key in seen_keys:
          if prior_key > entry_key:
            raise ValueError("parameters must be sorted by their key")
      
      results[entry_key] = entry_value
      seen_keys.append(entry_key)
    except ValueError, exc:
      if not validate:
        continue
      
      raise ValueError("Unable to parse network status document's '%s' line (%s): %s'" % (keyword, exc, value))
  
  return results


class DirectoryAuthority(stem.descriptor.Descriptor):
  """
  Directory authority information obtained from a v3 network status document.
  
  :var str nickname: **\*** authority's nickname
  :var str fingerprint: **\*** authority's fingerprint
  :var str hostname: **\*** hostname of the authority
  :var str address: **\*** authority's IP address
  :var int dir_port: **\*** authority's DirPort
  :var int or_port: **\*** authority's ORPort
  :var str contact: **\*** contact information
  
  **Consensus Attributes:**
  
  :var str vote_digest: **\*** digest of the authority that contributed to the consensus
  
  **Vote Attributes:**
  
  :var str legacy_dir_key: fingerprint of and obsolete identity key
  :var stem.descriptor.networkstatus.KeyCertificate key_certificate: **\***
    authority's key certificate
  
  **\*** mandatory attribute
  """
  
  def __init__(self, raw_content, validate = True, is_vote = False):
    """
    Parse a directory authority entry in a v3 network status document.
    
    :param str raw_content: raw directory authority entry information
    :param bool validate: checks the validity of the content if True, skips
      these checks otherwise
    :param bool is_vote: True if this is for a vote, False if it's for a consensus
    
    :raises: ValueError if the descriptor data is invalid
    """
    
    super(DirectoryAuthority, self).__init__(raw_content)
    
    self.nickname = None
    self.fingerprint = None
    self.hostname = None
    self.address = None
    self.dir_port = None
    self.or_port = None
    self.contact = None
    
    self.vote_digest = None
    
    self.legacy_dir_key = None
    self.key_certificate = None
    
    self._unrecognized_lines = []
    
    self._parse(raw_content, validate, is_vote)
  
  def _parse(self, content, validate, is_vote):
    """
    Parses the given content and applies the attributes.
    
    :param str content: descriptor content
    :param bool validate: checks validity if True
    :param bool is_vote: **True** if this is for a vote, **False** if it's for
      a consensus
    
    :raises: **ValueError** if a validity check fails
    """
    
    # separate the directory authority entry from its key certificate
    key_div = content.find('\ndir-key-certificate-version')
    
    if key_div != -1:
      key_cert_content = content[key_div + 1:]
      content = content[:key_div + 1]
    else:
      key_cert_content = None
    
    entries = stem.descriptor._get_descriptor_components(content, validate)
    
    if validate and 'dir-source' != entries.keys()[0]:
      raise ValueError("Authority entries are expected to start with a 'dir-source' line:\n%s" % (content))
    
    # check that we have mandatory fields
    
    if validate:
      required_fields, excluded_fields = ["dir-source", "contact"], []
      
      if is_vote:
        if not key_cert_content:
          raise ValueError("Authority votes must have a key certificate:\n%s" % content)
        
        excluded_fields += ["vote-digest"]
      elif not is_vote:
        if key_cert_content:
          raise ValueError("Authority consensus entries shouldn't have a key certificate:\n%s" % content)
        
        required_fields += ["vote-digest"]
        excluded_fields += ["legacy-dir-key"]
      
      for keyword in required_fields:
        if not keyword in entries:
          raise ValueError("Authority entries must have a '%s' line:\n%s" % (keyword, content))
      
      for keyword in entries:
        if keyword in excluded_fields:
          type_label = "votes" if is_vote else "consensus entries"
          raise ValueError("Authority %s shouldn't have a '%s' line:\n%s" % (type_label, keyword, content))
    
    for keyword, values in entries.items():
      value, _ = values[0]
      line = "%s %s" % (keyword, value)
      
      # all known attributes can only appear at most once
      if validate and len(values) > 1 and keyword in ('dir-source', 'contact', 'legacy-dir-key', 'vote-digest'):
        raise ValueError("Authority entries can only have a single '%s' line, got %i:\n%s" % (keyword, len(values), content))
      
      if keyword == 'dir-source':
        # "dir-source" nickname identity address IP dirport orport
        
        dir_source_comp = value.split(" ")
        
        if len(dir_source_comp) < 6:
          if not validate:
            continue
          
          raise ValueError("Authority entry's 'dir-source' line must have six values: %s" % line)
        
        if validate:
          if not stem.util.tor_tools.is_valid_nickname(dir_source_comp[0]):
            raise ValueError("Authority's nickname is invalid: %s" % dir_source_comp[0])
          elif not stem.util.tor_tools.is_valid_fingerprint(dir_source_comp[1]):
            raise ValueError("Authority's fingerprint is invalid: %s" % dir_source_comp[1])
          elif not dir_source_comp[2]:
            # https://trac.torproject.org/7055
            raise ValueError("Authority's hostname can't be blank: %s" % line)
          elif not stem.util.connection.is_valid_ip_address(dir_source_comp[3]):
            raise ValueError("Authority's address isn't a valid IPv4 address: %s" % dir_source_comp[3])
          elif not stem.util.connection.is_valid_port(dir_source_comp[4], allow_zero = True):
            raise ValueError("Authority's DirPort is invalid: %s" % dir_source_comp[4])
          elif not stem.util.connection.is_valid_port(dir_source_comp[5]):
            raise ValueError("Authority's ORPort is invalid: %s" % dir_source_comp[5])
        elif not (dir_source_comp[4].isdigit() and dir_source_comp[5].isdigit()):
          continue
        
        self.nickname = dir_source_comp[0]
        self.fingerprint = dir_source_comp[1]
        self.hostname = dir_source_comp[2]
        self.address = dir_source_comp[3]
        self.dir_port = None if dir_source_comp[4] == '0' else int(dir_source_comp[4])
        self.or_port = int(dir_source_comp[5])
      elif keyword == 'contact':
        # "contact" string
        
        self.contact = value
      elif keyword == 'legacy-dir-key':
        # "legacy-dir-key" FINGERPRINT
        
        if validate and not stem.util.tor_tools.is_valid_fingerprint(value):
          raise ValueError("Authority has a malformed legacy directory key: %s" % line)
        
        self.legacy_dir_key = value
      elif keyword == 'vote-digest':
        # "vote-digest" digest
        
        # technically not a fingerprint, but has the same characteristics
        if validate and not stem.util.tor_tools.is_valid_fingerprint(value):
          raise ValueError("Authority has a malformed vote digest: %s" % line)
        
        self.vote_digest = value
      else:
        self._unrecognized_lines.append(line)
    
    if key_cert_content:
      self.key_certificate = KeyCertificate(key_cert_content, validate)
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self._unrecognized_lines
  
  def __cmp__(self, other):
    if not isinstance(other, DirectoryAuthority):
      return 1
    
    return str(self) > str(other)


class KeyCertificate(stem.descriptor.Descriptor):
  """
  Directory key certificate for a v3 network status document.
  
  :var int version: **\*** version of the key certificate
  :var str address: authority's IP address
  :var int dir_port: authority's DirPort
  :var str fingerprint: **\*** authority's fingerprint
  :var str identity_key: **\*** long term authority identity key
  :var datetime published: **\*** time when this key was generated
  :var datetime expires: **\*** time after which this key becomes invalid
  :var str signing_key: **\*** directory server's public signing key
  :var str crosscert: signature made using certificate's signing key
  :var str certification: **\*** signature of this key certificate signed with
    the identity key
  
  **\*** mandatory attribute
  """
  
  def __init__(self, raw_content, validate = True):
    super(KeyCertificate, self).__init__(raw_content)
    
    self.version = None
    self.address = None
    self.dir_port = None
    self.fingerprint = None
    self.identity_key = None
    self.published = None
    self.expires = None
    self.signing_key = None
    self.crosscert = None
    self.certification = None
    
    self._unrecognized_lines = []
    
    self._parse(raw_content, validate)
  
  def _parse(self, content, validate):
    """
    Parses the given content and applies the attributes.
    
    :param str content: descriptor content
    :param bool validate: checks validity if **True**
    
    :raises: **ValueError** if a validity check fails
    """
    
    entries = stem.descriptor._get_descriptor_components(content, validate)
    
    if validate:
      if 'dir-key-certificate-version' != entries.keys()[0]:
        raise ValueError("Key certificates must start with a 'dir-key-certificate-version' line:\n%s" % (content))
      elif 'dir-key-certification' != entries.keys()[-1]:
        raise ValueError("Key certificates must end with a 'dir-key-certification' line:\n%s" % (content))
      
      # check that we have mandatory fields and that our known fields only
      # appear once
      
      for keyword, is_mandatory in KEY_CERTIFICATE_PARAMS:
        if is_mandatory and not keyword in entries:
          raise ValueError("Key certificates must have a '%s' line:\n%s" % (keyword, content))
        
        entry_count = len(entries.get(keyword, []))
        if entry_count > 1:
          raise ValueError("Key certificates can only have a single '%s' line, got %i:\n%s" % (keyword, entry_count, content))
    
    for keyword, values in entries.items():
      value, block_contents = values[0]
      line = "%s %s" % (keyword, value)
      
      if keyword == 'dir-key-certificate-version':
        # "dir-key-certificate-version" version
        
        if not value.isdigit():
          if not validate:
            continue
          
          raise ValueError("Key certificate has a non-integer version: %s" % line)
        
        self.version = int(value)
        
        if validate and self.version != 3:
          raise ValueError("Expected a version 3 key certificate, got version '%i' instead" % self.version)
      elif keyword == 'dir-address':
        # "dir-address" IPPort
        
        if not ':' in value:
          if not validate:
            continue
          
          raise ValueError("Key certificate's 'dir-address' is expected to be of the form ADDRESS:PORT: %s" % line)
        
        address, dirport = value.split(':', 1)
        
        if validate:
          if not stem.util.connection.is_valid_ip_address(address):
            raise ValueError("Key certificate's address isn't a valid IPv4 address: %s" % line)
          elif not stem.util.connection.is_valid_port(dirport):
            raise ValueError("Key certificate's dirport is invalid: %s" % line)
        elif not dirport.isdigit():
          continue
        
        self.address = address
        self.dir_port = int(dirport)
      elif keyword == 'fingerprint':
        # "fingerprint" fingerprint
        
        if validate and not stem.util.tor_tools.is_valid_fingerprint(value):
          raise ValueError("Key certificate's fingerprint is malformed: %s" % line)
        
        self.fingerprint = value
      elif keyword in ('dir-key-published', 'dir-key-expires'):
        # "dir-key-published" YYYY-MM-DD HH:MM:SS
        # "dir-key-expires" YYYY-MM-DD HH:MM:SS
        
        try:
          date_value = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
          
          if keyword == 'dir-key-published':
            self.published = date_value
          elif keyword == 'dir-key-expires':
            self.expires = date_value
        except ValueError:
          if validate:
            raise ValueError("Key certificate's '%s' time wasn't parsable: %s" % (keyword, value))
      elif keyword in ('dir-identity-key', 'dir-signing-key', 'dir-key-crosscert', 'dir-key-certification'):
        # "dir-identity-key" NL a public key in PEM format
        # "dir-signing-key" NL a key in PEM format
        # "dir-key-crosscert" NL CrossSignature
        # "dir-key-certification" NL Signature
        
        if validate and not block_contents:
          raise ValueError("Key certificate's '%s' line must be followed by a key block: %s" % (keyword, line))
        
        if keyword == 'dir-identity-key':
          self.identity_key = block_contents
        elif keyword == 'dir-signing-key':
          self.signing_key = block_contents
        elif keyword == 'dir-key-crosscert':
          self.crosscert = block_contents
        elif keyword == 'dir-key-certification':
          self.certification = block_contents
      else:
        self._unrecognized_lines.append(line)
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: **list** of unrecognized lines
    """
    
    return self._unrecognized_lines
  
  def __cmp__(self, other):
    if not isinstance(other, KeyCertificate):
      return 1
    
    return str(self) > str(other)


class DocumentSignature(object):
  """
  Directory signature of a v3 network status document.
  
  :var str method: algorithm used to make the signature
  :var str identity: fingerprint of the authority that made the signature
  :var str key_digest: digest of the signing key
  :var str signature: document signature
  :param bool validate: checks validity if **True**
  
  :raises: **ValueError** if a validity check fails
  """
  
  def __init__(self, method, identity, key_digest, signature, validate = True):
    # Checking that these attributes are valid. Technically the key
    # digest isn't a fingerprint, but it has the same characteristics.
    
    if validate:
      if not stem.util.tor_tools.is_valid_fingerprint(identity):
        raise ValueError("Malformed fingerprint (%s) in the document signature" % (identity))
      
      if not stem.util.tor_tools.is_valid_fingerprint(key_digest):
        raise ValueError("Malformed key digest (%s) in the document signature" % (key_digest))
    
    self.method = method
    self.identity = identity
    self.key_digest = key_digest
    self.signature = signature
  
  def __cmp__(self, other):
    if not isinstance(other, DocumentSignature):
      return 1
    
    for attr in ("identity", "key_digest", "signature"):
      if getattr(self, attr) > getattr(other, attr):
        return 1
      elif getattr(self, attr) < getattr(other, attr):
        return -1
    
    return 0
