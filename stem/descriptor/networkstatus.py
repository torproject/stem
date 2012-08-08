"""
Parsing for Tor network status documents. Currently supports parsing v3 network
status documents (both votes and consensuses).

The network status documents also contain a list of router descriptors,
directory authorities, signatures etc. If you only need the
:class:`stem.descriptor.networkstatus.RouterDescriptor` objects, use
:func:`stem.descriptor.parse_file`. Other information can be accessed by
directly instantiating :class:`stem.descriptor.networkstatus.NetworkStatusDocument`
objects.

The documents can be obtained from any of the following sources...

* the 'cached-consensus' file in tor's data directory
* tor metrics, at https://metrics.torproject.org/data.html
* directory authorities and mirrors via their DirPort

::

  import stem.descriptor.networkstatus
  
  nsdoc_file = open("/home/neena/.tor/cached-consensus")
  try:
    consensus = stem.descriptor.networkstatus.NetworkStatusDocument(nsdoc_file.read())
  except ValueError:
    print "Invalid cached-consensus file"
  
  print "Consensus was valid between %s and %s" % (str(consensus.valid_after), str(consensus.valid_until))

**Module Overview:**

::

  parse_file - parses a network status file and provides a NetworkStatusDocument
  NetworkStatusDocument - Tor v3 network status document
  RouterDescriptor - Router descriptor; contains information about a Tor relay
  DirectorySignature - Network status document's directory signature
  DirectoryAuthority - Directory authority defined in a v3 network status document
"""

import re
import datetime
from StringIO import StringIO

import stem.descriptor
import stem.version
import stem.exit_policy

from stem.descriptor import _read_until_keywords, _skip_until_keywords, _peek_keyword

_bandwidth_weights_regex = re.compile(" ".join(["W%s=\d+" % weight for weight in ["bd",
  "be", "bg", "bm", "db", "eb", "ed", "ee", "eg", "em", "gb", "gd", "gg", "gm", "mb", "md", "me", "mg", "mm"]]))

_router_desc_end_kws = ["r", "bandwidth-weights", "directory-footer", "directory-signature"]

def parse_file(document_file, validate = True):
  """
  Iterates over the router descriptors in a network status document.
  
  :param file document_file: file with network status document content
  :param bool validate: checks the validity of the document's contents if True, skips these checks otherwise
  
  :returns: iterator for :class:`stem.descriptor.networkstatus.RouterDescriptor` instances in the file
  
  :raises:
    * ValueError if the contents is malformed and validate is True
    * IOError if the file can't be read
  """
  
  # parse until "r"
  document_data = "".join(_read_until_keywords("r", document_file))
  # store offset
  r_offset = document_file.tell()
  # skip until end of router descriptors
  _skip_until_keywords(["bandwidth-weights", "directory-footer", "directory-signature"], document_file)
  # parse until end
  document_data = document_data + document_file.read()
  document = NetworkStatusDocument(document_data, validate)
  document_file.seek(r_offset)
  document.router_descriptors = _router_desc_generator(document_file, document.vote_status == "vote", validate)
  return document.router_descriptors

def _strptime(string, validate = True, optional = False):
  try:
    return datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
  except ValueError, exc:
    if validate or not optional: raise exc
    else: return None

def _router_desc_generator(document_file, vote, validate):
  while _peek_keyword(document_file) == "r":
    desc_content = "".join(_read_until_keywords(_router_desc_end_kws, document_file, False, True))
    yield RouterDescriptor(desc_content, vote, validate)

class NetworkStatusDocument(stem.descriptor.Descriptor):
  """
  A v3 network status document.
  
  This could be a v3 consensus or vote document.
  
  :var bool validated: **\*** whether the document is validated
  :var str network_status_version: **\*** a document format version. For v3 documents this is "3"
  :var str vote_status: **\*** status of the vote (is either "vote" or "consensus")
  :var list consensus_methods: **^** A list of supported consensus generation methods (integers)
  :var datetime published: **^** time when the document was published
  :var int consensus_method: **~** consensus method used to generate a consensus
  :var datetime valid_after: **\*** time when the consensus becomes valid
  :var datetime fresh_until: **\*** time until when the consensus is considered to be fresh
  :var datetime valid_until: **\*** time until when the consensus is valid
  :var int vote_delay: **\*** number of seconds allowed for collecting votes from all authorities
  :var int dist_delay: number of seconds allowed for collecting signatures from all authorities
  :var list client_versions: list of recommended Tor client versions
  :var list server_versions: list of recommended Tor server versions
  :var list known_flags: **\*** list of known router flags
  :var list params: dict of parameter(str) => value(int) mappings
  :var list router_descriptors: **\*** iterator for RouterDescriptor objects defined in the document
  :var list directory_authorities: **\*** list of DirectoryAuthority objects that have generated this document
  :var dict bandwidth_weights: **~** dict of weight(str) => value(int) mappings
  :var list directory_signatures: **\*** list of signatures this document has
  
  | **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  | **^** attribute appears only in votes
  | **~** attribute appears only in consensuses
  """
  
  def __init__(self, raw_content, validate = True):
    """
    Parse a v3 network status document and provide a new NetworkStatusDocument object.
    
    :param str raw_content: raw network status document data
    :param bool validate: True if the document is to be validated, False otherwise
    
    :raises: ValueError if the document is invalid
    """
    
    super(NetworkStatusDocument, self).__init__(raw_content)
    
    self.router_descriptors = []
    self.directory_authorities = []
    self.directory_signatures = []
    self.validated = validate
    
    self.network_status_version = None
    self.vote_status = None
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
    self.params = {}
    self.bandwidth_weights = {}
    
    self._parse(raw_content)
  
  def _generate_router(self, raw_content, vote, validate):
    return RouterDescriptor(raw_content, vote, validate)
  
  def _validate_network_status_version(self):
    return self.network_status_version == "3"
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized trailing lines.
    
    :returns: a list of unrecognized trailing lines
    """
    
    return self._unrecognized_lines
  
  def _parse(self, raw_content):
    # preamble
    validate = self.validated
    doc_parser = stem.descriptor.DescriptorParser(raw_content, validate)
    
    read_keyword_line = lambda keyword, optional = False: setattr(self, keyword.replace("-", "_"), doc_parser.read_keyword_line(keyword, optional))
    
    map(read_keyword_line, ["network-status-version", "vote-status"])
    if validate and not self._validate_network_status_version():
      raise ValueError("Invalid network-status-version: %s" % self.network_status_version)
    
    if self.vote_status == "vote": vote = True
    elif self.vote_status == "consensus": vote = False
    elif validate: raise ValueError("Unrecognized document type specified in vote-status")
    
    if vote:
      read_keyword_line("consensus-methods", True)
      self.consensus_methods = [int(method) for method in self.consensus_methods.split(" ")]
      self.published = _strptime(doc_parser.read_keyword_line("published", True), validate, True)
    else:
      self.consensus_method = int(doc_parser.read_keyword_line("consensus-method", True))
    
    map(read_keyword_line, ["valid-after", "fresh-until", "valid-until"])
    self.valid_after = _strptime(self.valid_after, validate)
    self.fresh_until = _strptime(self.fresh_until, validate)
    self.valid_until = _strptime(self.valid_until, validate)
    voting_delay = doc_parser.read_keyword_line("voting-delay")
    self.vote_delay, self.dist_delay = [int(delay) for delay in voting_delay.split(" ")]
    
    client_versions = doc_parser.read_keyword_line("client-versions", True)
    if client_versions:
      self.client_versions = [stem.version.Version(version_string) for version_string in client_versions.split(",")]
    server_versions = doc_parser.read_keyword_line("server-versions", True)
    if server_versions:
      self.server_versions = [stem.version.Version(version_string) for version_string in server_versions.split(",")]
    self.known_flags = doc_parser.read_keyword_line("known-flags").split(" ")
    read_keyword_line("params", True)
    if self.params:
      self.params = dict([(param.split("=")[0], int(param.split("=")[1])) for param in self.params.split(" ")])
    
    # authority section
    while doc_parser.line.startswith("dir-source "):
      dirauth_data = doc_parser.read_until(["dir-source", "r", "directory-footer", "directory-signature", "bandwidth-weights"])
      self.directory_authorities.append(DirectoryAuthority(dirauth_data, vote, validate))
    
    # router descriptors
    if doc_parser.peek_keyword() == "r":
      router_descriptors_data = doc_parser.read_until(["bandwidth-weights", "directory-footer", "directory-signature"])
      self.router_descriptors = _router_desc_generator(StringIO(router_descriptors_data), vote, validate)
    
    # footer section
    if self.consensus_method > 9 or vote and filter(lambda x: x >= 9, self.consensus_methods):
      if doc_parser.line == "directory-footer":
        doc_parser.read_line()
      elif validate:
        raise ValueError("Network status document missing directory-footer")
    
    if not vote:
      read_keyword_line("bandwidth-weights", True)
      if _bandwidth_weights_regex.match(self.bandwidth_weights):
        self.bandwidth_weights = dict([(weight.split("=")[0], int(weight.split("=")[1])) for weight in self.bandwidth_weights.split(" ")])
      elif validate:
        raise ValueError("Invalid bandwidth-weights line")
    
    while doc_parser.line.startswith("directory-signature "):
      signature_data = doc_parser.read_until(["directory-signature"])
      self.directory_signatures.append(DirectorySignature(signature_data))
    
    self._unrecognized_lines = doc_parser.remaining()
    if validate and self._unrecognized_lines: raise ValueError("Unrecognized trailing data")

class DirectoryAuthority(stem.descriptor.Descriptor):
  """
  Contains directory authority information obtained from v3 network status
  documents.
  
  :var str nickname: directory authority's nickname
  :var str identity: uppercase hex fingerprint of the authority's identity key
  :var str address: hostname
  :var str ip: current IP address
  :var int dirport: current directory port
  :var int orport: current orport
  :var str contact: directory authority's contact information
  :var str legacy_dir_key: **^** fingerprint of and obsolete identity key
  :var :class:`stem.descriptor.KeyCertificate` key_certificate: **^** directory authority's current key certificate
  :var str vote_digest: **~** digest of the authority that contributed to the consensus
  
  | **^** attribute appears only in votes
  | **~** attribute appears only in consensuses
  | legacy_dir_key is the only optional attribute
  """
  
  def __init__(self, raw_content, vote = True, validate = True):
    """
    Parse a directory authority entry in a v3 network status document and
    provide a DirectoryAuthority object.
    
    :param str raw_content: raw directory authority entry information
    :param bool validate: True if the document is to be validated, False otherwise
    
    :raises: ValueError if the raw data is invalid
    """
    
    super(DirectoryAuthority, self).__init__(raw_content)
    self.nickname, self.identity, self.address, self.ip = None, None, None, None
    self.dirport, self.orport, self.legacy_dir_key = None, None, None
    self.key_certificate, self.contact, self.vote_digest = None, None, None
    parser = stem.descriptor.DescriptorParser(raw_content, validate)
    
    dir_source = parser.read_keyword_line("dir-source")
    self.nickname, self.identity, self.address, self.ip, self.dirport, self.orport = dir_source.split(" ")
    self.dirport = int(self.dirport)
    self.orport = int(self.orport)
    
    self.contact = parser.read_keyword_line("contact")
    if vote:
      self.legacy_dir_key = parser.read_keyword_line("legacy-dir-key", True)
      self.key_certificate = stem.descriptor.KeyCertificate("\n".join(parser.remaining()), validate)
    else:
      self.vote_digest = parser.read_keyword_line("vote-digest", True)
    self._unrecognized_lines = parser.remaining()
    if self._unrecognized_lines and validate:
      raise ValueError("Unrecognized trailing data in directory authority information")
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self._unrecognized_lines

class DirectorySignature(stem.descriptor.Descriptor):
  """
  Contains directory signatures in a v3 network status document.
  
  :var str identity: signature identity
  :var str key_digest: signature key digest
  :var str method: method used to generate the signature
  :var str signature: the signature data
  """
  
  def __init__(self, raw_content, validate = True):
    """
    Parse a directory signature entry in a v3 network status document and
    provide a DirectorySignature object.
    
    :param str raw_content: raw directory signature entry information
    :param bool validate: True if the document is to be validated, False otherwise
    
    :raises: ValueError if the raw data is invalid
    """
    
    super(DirectorySignature, self).__init__(raw_content)
    self.identity, self.key_digest, self.method, self.signature = None, None, None, None
    parser = stem.descriptor.DescriptorParser(raw_content, validate)
    
    signature_line = parser.read_keyword_line("directory-signature").split(" ")
    
    if len(signature_line) == 2:
      self.identity, self.key_digest = signature_line
    if len(signature_line) == 3: # for microdescriptor consensuses
      self.method, self.identity, self.key_digest = signature_line
    
    self.signature = parser.read_block("SIGNATURE")
    self._unrecognized_lines = parser.remaining()
    if self._unrecognized_lines and validate:
      raise ValueError("Unrecognized trailing data in directory signature")
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self._unrecognized_lines

class RouterDescriptor(stem.descriptor.Descriptor):
  """
  Router descriptor object. Parses and stores router information in a router
  entry read from a v3 network status document.
  
  :var str nickname: **\*** router's nickname
  :var str identity: **\*** router's identity
  :var str digest: **\*** router's digest
  :var datetime publication: **\*** router's publication
  :var str ip: **\*** router's IP address
  :var int orport: **\*** router's ORPort
  :var int dirport: **\*** router's DirPort
  
  :var bool is_valid: **\*** router is valid
  :var bool is_guard: **\*** router is suitable for use as an entry guard
  :var bool is_named: **\*** router is named
  :var bool is_unnamed: **\*** router is unnamed
  :var bool is_running: **\*** router is running and currently usable
  :var bool is_stable: **\*** router is stable, i.e., it's suitable for for long-lived circuits
  :var bool is_exit: **\*** router is an exit router
  :var bool is_fast: **\*** router is Fast, i.e., it's usable for high-bandwidth circuits
  :var bool is_authority: **\*** router is a directory authority
  :var bool supports_v2dir: **\*** router supports v2dir
  :var bool supports_v3dir: **\*** router supports v3dir
  :var bool is_hsdir: **\*** router is a hidden status
  :var bool is_badexit: **\*** router is marked a bad exit
  :var bool is_baddirectory: **\*** router is a bad directory
  
  :var :class:`stem.version.Version`,str version: Version of the Tor protocol this router is running
  
  :var int bandwidth: router's claimed bandwidth
  :var int measured_bandwidth: router's measured bandwidth
  
  :var :class:`stem.exit_policy.MicrodescriptorExitPolicy` exit_policy: router's exit policy
  
  :var str microdescriptor_hashes: a list of two-tuples with a list of consensus methods(int) that may produce the digest and a dict with algorithm(str) => digest(str) mappings. algorithm is the hashing algorithm (usually "sha256") that is used to produce digest (the base64 encoding of the hash of the router's microdescriptor with trailing =s omitted).
  
  | **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  | exit_policy appears only in votes
  """
  
  def __init__(self, raw_contents, vote = True, validate = True):
    """
    Parse a router descriptor in a v3 network status document and provide a new
    RouterDescriptor object.
    
    :param str raw_content: router descriptor content to be parsed
    :param bool validate: whether the router descriptor should be validated
    """
    
    super(RouterDescriptor, self).__init__(raw_contents)
    
    self.nickname = None
    self.identity = None
    self.digest = None
    self.publication = None
    self.ip = None
    self.orport = None
    self.dirport = None
    
    self.is_valid = False
    self.is_guard = False
    self.is_named = False
    self.is_unnamed = False
    self.is_running = False
    self.is_stable = False
    self.is_exit = False
    self.is_fast = False
    self.is_authority = False
    self.supports_v2dir = False
    self.supports_v3dir = False
    self.is_hsdir = False
    self.is_badexit = False
    self.is_baddirectory = False
    
    self.version = None
    
    self.bandwidth = None
    self.measured_bandwidth = None
    
    self.exit_policy = None
    
    self.microdescriptor_hashes = []
    
    self._parse(raw_contents, vote, validate)
  
  def _parse(self, raw_content, vote, validate):
    """
    :param dict raw_content: iptor contents to be applied
    :param bool validate: checks the validity of descriptor content if True
    
    :raises: ValueError if an error occures in validation
    """
    
    parser = stem.descriptor.DescriptorParser(raw_content, validate)
    seen_keywords = set()
    peek_check_kw = lambda keyword: keyword == parser.peek_keyword()
    
    r = parser.read_keyword_line("r")
    # r mauer BD7xbfsCFku3+tgybEZsg8Yjhvw itcuKQ6PuPLJ7m/Oi928WjO2j8g 2012-06-22 13:19:32 80.101.105.103 9001 0
    # "r" SP nickname SP identity SP digest SP publication SP IP SP ORPort SP DirPort NL
    seen_keywords.add("r")
    if r:
      values = r.split(" ")
      self.nickname, self.identity, self.digest = values[0], values[1], values[2]
      self.publication = _strptime(" ".join((values[3], values[4])), validate)
      self.ip, self.orport, self.dirport = values[5], int(values[6]), int(values[7])
      if self.dirport == 0: self.dirport = None
    elif validate: raise ValueError("Invalid router descriptor: empty 'r' line" )
    
    while parser.line:
      if peek_check_kw("s"):
        if "s" in seen_keywords: raise ValueError("Invalid router descriptor: 's' line appears twice")
        line = parser.read_keyword_line("s")
        if not line: continue
        seen_keywords.add("s")
        # s Named Running Stable Valid
        #A series of space-separated status flags, in *lexical order*
        flags = line.split(" ")
        flag_map = {
          "Valid": "is_valid",
          "Guard": "is_guard",
          "Named": "is_named",
          "Unnamed": "is_unnamed",
          "Running": "is_running",
          "Stable": "is_stable",
          "Exit": "is_exit",
          "Fast": "is_fast",
          "Authority": "is_authority",
          "V2Dir": "supports_v2dir",
          "V3Dir": "supports_v3dir",
          "HSDir": "is_hsdir",
          "BadExit": "is_badexit",
          "BadDirectory": "is_baddirectory",
        }
        map(lambda flag: setattr(self, flag_map[flag], True), flags)
        
        if self.is_unnamed: self.is_named = False
        elif self.is_named: self.is_unnamed = False
      
      elif peek_check_kw("v"):
        if "v" in seen_keywords: raise ValueError("Invalid router descriptor: 'v' line appears twice")
        line = parser.read_keyword_line("v", True)
        seen_keywords.add("v")
        # v Tor 0.2.2.35
        if line:
          if line.startswith("Tor "):
            self.version = stem.version.Version(line[4:])
          else:
            self.version = line
        elif validate: raise ValueError("Invalid router descriptor: empty 'v' line" )
      
      elif peek_check_kw("w"):
        if "w" in seen_keywords: raise ValueError("Invalid router descriptor: 'w' line appears twice")
        w = parser.read_keyword_line("w", True)
        # "w" SP "Bandwidth=" INT [SP "Measured=" INT] NL
        seen_keywords.add("w")
        if w:
          values = w.split(" ")
          if len(values) <= 2 and len(values) > 0:
            key, value = values[0].split("=")
            if key == "Bandwidth": self.bandwidth = int(value)
            elif validate: raise ValueError("Router descriptor contains invalid 'w' line: expected Bandwidth, read " + key)
            
            if len(values) == 2:
              key, value = values[1].split("=")
              if key == "Measured": self.measured_bandwidth = int(value)
              elif validate: raise ValueError("Router descriptor contains invalid 'w' line: expected Measured, read " + key)
          elif validate: raise ValueError("Router descriptor contains invalid 'w' line")
        elif validate: raise ValueError("Router descriptor contains empty 'w' line")
      
      elif peek_check_kw("p"):
        if "p" in seen_keywords: raise ValueError("Invalid router descriptor: 'p' line appears twice")
        p = parser.read_keyword_line("p", True)
        seen_keywords.add("p")
        # "p" SP ("accept" / "reject") SP PortList NL
        if p:
          self.exit_policy = stem.exit_policy.MicrodescriptorExitPolicy(p)
      
      elif vote and peek_check_kw("m"):
        # microdescriptor hashes
        m = parser.read_keyword_line("m", True)
        methods, digests = m.split(" ", 1)
        method_list = methods.split(",")
        digest_dict = [digest.split("=", 1) for digest in digests.split(" ")]
        self.microdescriptor_hashes.append((method_list, digest_dict))
      
      elif validate:
        raise ValueError("Router descriptor contains unrecognized trailing lines: %s" % parser.line)
      
      else:
        self._unrecognized_lines.append(parser.read_line()) # ignore unrecognized lines if we aren't validating
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self._unrecognized_lines

