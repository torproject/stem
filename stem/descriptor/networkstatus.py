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

try:
  from cStringIO import StringIO
except:
  from StringIO import StringIO

import stem.descriptor
import stem.version
import stem.exit_policy
import stem.util.enum

from stem.descriptor import _read_until_keywords, _skip_until_keywords, _peek_keyword, _strptime
from stem.descriptor import _read_keyword_line, _read_keyword_line_str, _get_pseudo_pgp_block, _peek_line

_bandwidth_weights_regex = re.compile(" ".join(["W%s=\d+" % weight for weight in ["bd",
  "be", "bg", "bm", "db", "eb", "ed", "ee", "eg", "em", "gb", "gd", "gg", "gm", "mb", "md", "me", "mg", "mm"]]))

_router_desc_end_kws = ["r", "bandwidth-weights", "directory-footer", "directory-signature"]

Flag = stem.util.enum.Enum(*[(flag.upper(), flag) for flag in ["Authority", "BadExit", "Exit", "Fast", "Guard", "HSDir", "Named", "Running", "Stable", "Unnamed", "V2Dir", "Valid"]])

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
  document.router_descriptors = _router_desc_generator(document_file, document.vote_status == "vote", validate, document.known_flags)
  return document.router_descriptors

def _router_desc_generator(document_file, vote, validate, known_flags):
  while _peek_keyword(document_file) == "r":
    desc_content = "".join(_read_until_keywords(_router_desc_end_kws, document_file, False, True))
    yield RouterDescriptor(desc_content, vote, validate, known_flags)

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
  
  def _generate_router(self, raw_content, vote, validate, known_flags):
    return RouterDescriptor(raw_content, vote, validate, known_flags)
  
  def _validate_network_status_version(self):
    return self.network_status_version == "3"
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized trailing lines.
    
    :returns: a list of unrecognized trailing lines
    """
    
    return self.unrecognized_lines
  
  def _parse(self, raw_content):
    # preamble
    content = StringIO(raw_content)
    validate = self.validated
    read_keyword_line = lambda keyword, optional = False: setattr(self, keyword.replace("-", "_"), _read_keyword_line(keyword, content, validate, optional))
    
    map(read_keyword_line, ["network-status-version", "vote-status"])
    if validate and not self._validate_network_status_version():
      raise ValueError("Invalid network-status-version: %s" % self.network_status_version)
    
    if self.vote_status == "vote": vote = True
    elif self.vote_status == "consensus": vote = False
    elif validate: raise ValueError("Unrecognized vote-status")
    
    if vote:
      read_keyword_line("consensus-methods", True)
      self.consensus_methods = [int(method) for method in self.consensus_methods.split(" ")]
      self.published = _strptime(_read_keyword_line("published", content, validate, True), validate, True)
    else:
      read_keyword_line("consensus-method", True)
      self.consensus_method = int(self.consensus_method)
    
    map(read_keyword_line, ["valid-after", "fresh-until", "valid-until"])
    self.valid_after = _strptime(self.valid_after, validate)
    self.fresh_until = _strptime(self.fresh_until, validate)
    self.valid_until = _strptime(self.valid_until, validate)
    voting_delay = _read_keyword_line("voting-delay", content, validate)
    self.vote_delay, self.dist_delay = [int(delay) for delay in voting_delay.split(" ")]
    
    client_versions = _read_keyword_line("client-versions", content, validate, True)
    if client_versions:
      self.client_versions = [stem.version.Version(version_string) for version_string in client_versions.split(",")]
    server_versions = _read_keyword_line("server-versions", content, validate, True)
    if server_versions:
      self.server_versions = [stem.version.Version(version_string) for version_string in server_versions.split(",")]
    self.known_flags = _read_keyword_line("known-flags", content, validate).split(" ")
    read_keyword_line("params", True)
    if self.params:
      self.params = dict([(param.split("=")[0], int(param.split("=")[1])) for param in self.params.split(" ")])
    
    # authority section
    while _peek_keyword(content) == "dir-source":
      dirauth_data = _read_until_keywords(["dir-source", "r", "directory-footer", "directory-signature", "bandwidth-weights"], content, False, True)
      dirauth_data = "".join(dirauth_data).rstrip()
      self.directory_authorities.append(DirectoryAuthority(dirauth_data, vote, validate))
    
    # router descriptors
    if _peek_keyword(content) == "r":
      router_descriptors_data = "".join(_read_until_keywords(["bandwidth-weights", "directory-footer", "directory-signature"], content, False, True))
      self.router_descriptors = _router_desc_generator(StringIO(router_descriptors_data), vote, validate, self.known_flags)
    
    # footer section
    if self.consensus_method > 9 or vote and filter(lambda x: x >= 9, self.consensus_methods):
      if _peek_keyword(content) == "directory-footer":
        content.readline()
      elif validate:
        raise ValueError("Network status document missing directory-footer")
    
    if not vote:
      read_keyword_line("bandwidth-weights", True)
      if _bandwidth_weights_regex.match(self.bandwidth_weights):
        self.bandwidth_weights = dict([(weight.split("=")[0], int(weight.split("=")[1])) for weight in self.bandwidth_weights.split(" ")])
      elif validate:
        raise ValueError("Invalid bandwidth-weights line")
    
    while _peek_keyword(content) == "directory-signature":
      signature_data = _read_until_keywords("directory-signature", content, False, True)
      self.directory_signatures.append(DirectorySignature("".join(signature_data)))
    
    self.unrecognized_lines = content.read()
    if validate and self.unrecognized_lines: raise ValueError("Unrecognized trailing data")

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
    
    content = StringIO(raw_content)
    dir_source = _read_keyword_line("dir-source", content, validate)
    self.nickname, self.identity, self.address, self.ip, self.dirport, self.orport = dir_source.split(" ")
    self.dirport = int(self.dirport)
    self.orport = int(self.orport)
    
    self.contact = _read_keyword_line("contact", content, validate)
    if vote:
      self.legacy_dir_key = _read_keyword_line("legacy-dir-key", content, validate, True)
      self.key_certificate = stem.descriptor.KeyCertificate(content.read(), validate)
    else:
      self.vote_digest = _read_keyword_line("vote-digest", content, True, validate)
    self.unrecognized_lines = content.read()
    if self.unrecognized_lines and validate:
      raise ValueError("Unrecognized trailing data in directory authority information")
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self.unrecognized_lines

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
    content = raw_content.splitlines()
    
    signature_line = _read_keyword_line_str("directory-signature", content, validate).split(" ")
    
    if len(signature_line) == 2:
      self.identity, self.key_digest = signature_line
    if len(signature_line) == 3:
      # for microdescriptor consensuses
      # This 'method' seems to be undocumented 8-8-12
      self.method, self.identity, self.key_digest = signature_line
    
    self.signature = _get_pseudo_pgp_block(content)
    self.unrecognized_lines = content
    if self.unrecognized_lines and validate:
      raise ValueError("Unrecognized trailing data in directory signature")
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self.unrecognized_lines

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
  
  :var list flags: **\*** list of status flags
  :var list unknown_flags: **\*** list of unidentified status flags
  
  :var :class:`stem.version.Version`,str version: Version of the Tor protocol this router is running
  
  :var int bandwidth: router's claimed bandwidth
  :var int measured_bandwidth: router's measured bandwidth
  
  :var :class:`stem.exit_policy.MicrodescriptorExitPolicy` exit_policy: router's exit policy
  
  :var str microdescriptor_hashes: a list of two-tuples with a list of consensus methods(int) that may produce the digest and a dict with algorithm(str) => digest(str) mappings. algorithm is the hashing algorithm (usually "sha256") that is used to produce digest (the base64 encoding of the hash of the router's microdescriptor with trailing =s omitted).
  
  | **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  | exit_policy appears only in votes
  """
  
  def __init__(self, raw_contents, vote = True, validate = True, known_flags = Flag):
    """
    Parse a router descriptor in a v3 network status document and provide a new
    RouterDescriptor object.
    
    :param str raw_content: router descriptor content to be parsed
    :param bool vote: True if the descriptor is from a vote document
    :param bool validate: whether the router descriptor should be validated
    :param bool known_flags: list of known router status flags

    :raises: ValueError if the descriptor data is invalid
    """
    
    super(RouterDescriptor, self).__init__(raw_contents)
    
    self.nickname = None
    self.identity = None
    self.digest = None
    self.publication = None
    self.ip = None
    self.orport = None
    self.dirport = None
    
    self.flags = []
    self.unknown_flags = []
    
    self.version = None
    
    self.bandwidth = None
    self.measured_bandwidth = None
    
    self.exit_policy = None
    
    self.microdescriptor_hashes = []
    
    self._parse(raw_contents, vote, validate, known_flags)
  
  def _parse(self, raw_content, vote, validate, known_flags):
    """
    :param dict raw_content: iptor contents to be applied
    :param bool vote: True if the descriptor is from a vote document
    :param bool validate: checks the validity of descriptor content if True
    :param bool known_flags: list of known router status flags
    
    :raises: ValueError if an error occures in validation
    """
    
    content = StringIO(raw_content)
    seen_keywords = set()
    peek_check_kw = lambda keyword: keyword == _peek_keyword(content)
    
    r = _read_keyword_line("r", content, validate)
    # r mauer BD7xbfsCFku3+tgybEZsg8Yjhvw itcuKQ6PuPLJ7m/Oi928WjO2j8g 2012-06-22 13:19:32 80.101.105.103 9001 0
    # "r" SP nickname SP identity SP digest SP publication SP IP SP ORPort SP DirPort NL
    if r:
      seen_keywords.add("r")
      values = r.split(" ")
      self.nickname, self.identity, self.digest = values[0], values[1], values[2]
      self.publication = _strptime(" ".join((values[3], values[4])), validate)
      self.ip, self.orport, self.dirport = values[5], int(values[6]), int(values[7])
      if self.dirport == 0: self.dirport = None
    elif validate: raise ValueError("Invalid router descriptor: empty 'r' line")
    
    while _peek_line(content):
      if peek_check_kw("s"):
        if "s" in seen_keywords: raise ValueError("Invalid router descriptor: 's' line appears twice")
        line = _read_keyword_line("s", content, validate)
        if not line: continue
        seen_keywords.add("s")
        # s Named Running Stable Valid
        #A series of space-separated status flags, in *lexical order*
        self.flags = line.split(" ")
        
        self.unknown_flags = filter(lambda f: not f in known_flags, self.flags)
        if validate and self.unknown_flags:
          raise ValueError("Router contained unknown flags: %s", " ".join(self.unknown_flags))
      
      elif peek_check_kw("v"):
        if "v" in seen_keywords: raise ValueError("Invalid router descriptor: 'v' line appears twice")
        line = _read_keyword_line("v", content, validate, True)
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
        w = _read_keyword_line("w", content, validate, True)
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
        p = _read_keyword_line("p", content, validate, True)
        seen_keywords.add("p")
        # "p" SP ("accept" / "reject") SP PortList NL
        if p:
          self.exit_policy = stem.exit_policy.MicrodescriptorExitPolicy(p)
      
      elif vote and peek_check_kw("m"):
        # microdescriptor hashes
        m = _read_keyword_line("m", content, validate, True)
        methods, digests = m.split(" ", 1)
        method_list = methods.split(",")
        digest_dict = [digest.split("=", 1) for digest in digests.split(" ")]
        self.microdescriptor_hashes.append((method_list, digest_dict))
      
      elif validate:
        raise ValueError("Router descriptor contains unrecognized trailing lines: %s" % content.readline())
      
      else:
        self.unrecognized_lines.append(content.readline()) # ignore unrecognized lines if we aren't validating
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self.unrecognized_lines

