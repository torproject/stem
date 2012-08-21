"""
Parsing for Tor network status documents. Currently supports parsing v3 network
status documents (both votes and consensuses).

The network status documents also contain a list of router descriptors,
directory authorities, signatures etc. If you only need the
:class:`stem.descriptor.networkstatus.RouterStatusEntry` objects, use
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
    consensus = stem.descriptor.networkstatus.parse_file(nsdoc_file)
  except ValueError:
    print "Invalid cached-consensus file"
  
  print "Consensus was valid between %s and %s" % (str(consensus.valid_after), str(consensus.valid_until))

**Module Overview:**

::

  parse_file - parses a network status file and provides a NetworkStatusDocument
  NetworkStatusDocument - Tor v3 network status document
    +- MicrodescriptorConsensus - Microdescriptor flavoured consensus documents
  RouterStatusEntry - Router descriptor; contains information about a Tor relay
    +- RouterMicrodescriptor - Router microdescriptor; contains information that doesn't change frequently
  DirectorySignature - Network status document's directory signature
  DirectoryAuthority - Directory authority defined in a v3 network status document
"""

import re
import base64
import datetime

try:
  from cStringIO import StringIO
except:
  from StringIO import StringIO

import stem.descriptor
import stem.version
import stem.exit_policy
import stem.util.enum
import stem.util.tor_tools

from stem.descriptor import _read_until_keywords, _peek_keyword, _strptime
from stem.descriptor import _read_keyword_line, _read_keyword_line_str, _get_pseudo_pgp_block, _peek_line

_bandwidth_weights_regex = re.compile(" ".join(["W%s=\d+" % weight for weight in ["bd",
  "be", "bg", "bm", "db", "eb", "ed", "ee", "eg", "em", "gb", "gd", "gg", "gm", "mb", "md", "me", "mg", "mm"]]))

Flag = stem.util.enum.Enum(
  ("AUTHORITY", "Authority"),
  ("BADEXIT", "BadExit"),
  ("EXIT", "Exit"),
  ("FAST", "Fast"),
  ("GUARD", "Guard"),
  ("HSDIR", "HSDir"),
  ("NAMED", "Named"),
  ("RUNNING", "Running"),
  ("STABLE", "Stable"),
  ("UNNAMED", "Unnamed"),
  ("V2DIR", "V2Dir"),
  ("VALID", "Valid"),
)

def parse_file(document_file, validate = True, is_microdescriptor = False):
  """
  Parses a network status and iterates over the RouterStatusEntry or
  RouterMicrodescriptor in it. The document that these instances reference have
  an empty 'rotuers' attribute to allow for limited memory usage.
  
  :param file document_file: file with network status document content
  :param bool validate: checks the validity of the document's contents if True, skips these checks otherwise
  :param bool is_microdescriptor: True if this is for a microdescriptor consensus, False otherwise
  
  :returns: :class:`stem.descriptor.networkstatus.NetworkStatusDocument` object
  
  :raises:
    * ValueError if the contents is malformed and validate is True
    * IOError if the file can't be read
  """
  
  header, footer, routers_end = _get_document_content(document_file, validate)
  document_data = "".join(header + footer)
  
  if not is_microdescriptor:
    document = NetworkStatusDocument(document_data, validate)
    router_type = RouterStatusEntry
  else:
    document = MicrodescriptorConsensus(document_data, validate)
    router_type = RouterMicrodescriptor
  
  for desc in _get_routers(document_file, validate, document, routers_end, router_type):
    yield desc

def _get_document_content(document_file, validate):
  """
  Network status documents consist of three sections: header, router entries,
  and the footer. This provides back a tuple with the following...
  (header_lines, footer_lines, routers_end)
  
  This leaves the document_file at the start of the router entries.
  
  :param file document_file: file with network status document content
  :param bool validate: checks the validity of the document's contents if True, skips these checks otherwise
  
  :returns: tuple with the network status document content and ending position of the routers
  
  :raises:
    * ValueError if the contents is malformed and validate is True
    * IOError if the file can't be read
  """
  
  # parse until the first router record
  
  header = _read_until_keywords("r", document_file)
  routers_start = document_file.tell()
  
  # figure out the network status version
  
  # TODO: we should pick either 'directory-footer' or 'directory-signature'
  # based on the header's network-status-version
  
  _read_until_keywords(["directory-footer", "directory-signature"], document_file, skip = True)
  routers_end = document_file.tell()
  footer = document_file.readlines()
  
  document_file.seek(routers_start)
  return (header, footer, routers_end)

def _get_routers(document_file, validate, document, end_position, router_type):
  """
  Iterates over the router entries in a given document. The document_file is
  expected to be at the start of the router section and the end_position
  desigates where that section ends.
  
  :param file document_file: file with network status document content
  :param bool validate: checks the validity of the document's contents if True, skips these checks otherwise
  :param object document: document the descriptors originate from
  :param int end_position: location in the document_file where the router section ends
  :param class router_type: router class to construct
  
  :returns: iterator over router_type instances
  
  :raises:
    * ValueError if the contents is malformed and validate is True
    * IOError if the file can't be read
  """
  
  while document_file.tell() < end_position:
    desc_content = "".join(_read_until_keywords("r", document_file, ignore_first = True, end_position = end_position))
    yield router_type(desc_content, document, validate)

class NetworkStatusDocument(stem.descriptor.Descriptor):
  """
  A v3 network status document.
  
  This could be a v3 consensus or vote document.
  
  :var tuple routers: RouterStatusEntry contained in the document
  
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
    
    document_file = StringIO(raw_content)
    header, footer, routers_end = _get_document_content(document_file, validate)
    
    document_content = "".join(header + footer)
    self._parse(document_content)
    
    if document_file.tell() < routers_end:
      self.routers = tuple(_get_routers(document_file, validate, self, routers_end, self._get_router_type()))
    else:
      self.routers = ()
  
  def _get_router_type(self):
    return RouterStatusEntry
  
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
  :var str fingerprint: uppercase hex fingerprint of the authority's identity key
  :var str address: hostname
  :var str ip: current IP address
  :var int dir_port: current directory port
  :var int or_port: current orport
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
    self.nickname, self.fingerprint, self.address, self.ip = None, None, None, None
    self.dir_port, self.or_port, self.legacy_dir_key = None, None, None
    self.key_certificate, self.contact, self.vote_digest = None, None, None
    
    content = StringIO(raw_content)
    dir_source = _read_keyword_line("dir-source", content, validate)
    self.nickname, self.fingerprint, self.address, self.ip, self.dir_port, self.or_port = dir_source.split(" ")
    self.dir_port = int(self.dir_port)
    self.or_port = int(self.or_port)
    
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

class RouterStatusEntry(stem.descriptor.Descriptor):
  """
  Information about an individual router stored within a network status
  document.
  
  :var NetworkStatusDocument document: **\*** document that this descriptor came from
  
  :var str nickname: **\*** router's nickname
  :var str fingerprint: **\*** router's fingerprint
  :var str digest: **\*** router's digest
  :var datetime publication: **\*** router's publication
  :var str address: **\*** router's IP address
  :var int or_port: **\*** router's ORPort
  :var int dir_port: **\*** router's DirPort
  :var list flags: **\*** list of status flags
  
  :var stem.version.Version version: parsed version of tor, this is None if the relay's using a new versioning scheme
  :var str version_line: versioning information reported by the relay
  
  :var int bandwidth: bandwidth claimed by the relay (in kb/s)
  :var int measured: bandwith measured to be available by the relay
  :var list unrecognized_bandwidth_entries: **\*** bandwidth weighting information that isn't yet recognized
  
  :var stem.exit_policy.MicrodescriptorExitPolicy exit_policy: router's exit policy
  
  :var list microdescriptor_hashes: tuples of two values, the list of consensus methods for generting a set of digests and the 'algorithm => digest' mappings
  
  **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  """
  
  def __init__(self, raw_contents, document, validate = True):
    """
    Parse a router descriptor in a v3 network status document.
    
    :param str raw_content: router descriptor content to be parsed
    :param NetworkStatusDocument document: document this descriptor came from
    :param bool validate: checks the validity of the content if True, skips these checks otherwise
    
    :raises: ValueError if the descriptor data is invalid
    """
    
    super(RouterStatusEntry, self).__init__(raw_contents)
    
    self.document = document
    
    self.nickname = None
    self.fingerprint = None
    self.digest = None
    self.publication = None
    self.address = None
    self.or_port = None
    self.dir_port = None
    
    self.flags = None
    
    self.version_line = None
    self.version = None
    
    self.bandwidth = None
    self.measured = None
    self.unrecognized_bandwidth_entries = []
    
    self.exit_policy = None
    self.microdescriptor_hashes = None
    self.unrecognized_lines = []
    
    self._parse(raw_contents, validate)
  
  def _parse(self, content, validate):
    """
    Parses the given content and applies the attributes.
    
    :param str content: descriptor content
    :param bool validate: checks validity if True
    
    :raises: ValueError if a validity check fails
    """
    
    entries = _get_entries(content, validate, 'r')
    
    # check that we have mandatory fields
    if validate:
      for keyword in ('r', 's'):
        if not keyword in entries:
          raise ValueError("Router status entries must have a '%s' line:\n%s" % (keyword, content))
    
    for keyword, values in entries.items():
      value = values[0]
      line = "%s %s" % (keyword, value)
      
      # most attributes can only appear at most once
      if validate and len(values) > 1 and keyword in ('r', 's', 'v', 'w', 'p'):
        raise ValueError("Router status entries can only have a single '%s' line, got %i:\n%s" % (key, len(values), content))
      
      if keyword == 'r':
        # "r" nickname identity digest publication IP ORPort DirPort
        # r mauer BD7xbfsCFku3+tgybEZsg8Yjhvw itcuKQ6PuPLJ7m/Oi928WjO2j8g 2012-06-22 13:19:32 80.101.105.103 9001 0
        
        r_comp = value.split(" ")
        
        if len(r_comp) < 5:
          if not validate: continue
          raise ValueError("Router status entry's 'r' line line must have eight values: %s" % line)
        
        if validate:
          if not stem.util.tor_tools.is_valid_nickname(r_comp[0]):
            raise ValueError("Router status entry's nickname isn't valid: %s" % r_comp[0])
          elif not stem.util.connection.is_valid_ip_address(r_comp[5]):
            raise ValueError("Router status entry's address isn't a valid IPv4 address: %s" % r_comp[5])
          elif not stem.util.connection.is_valid_port(r_comp[6]):
            raise ValueError("Router status entry's ORPort is invalid: %s" % r_comp[6])
          elif not stem.util.connection.is_valid_port(r_comp[7], allow_zero = True):
            raise ValueError("Router status entry's DirPort is invalid: %s" % r_comp[7])
        elif not (r_comp[6].isdigit() and r_comp[7].isdigit()):
          continue
        
        self.nickname    = r_comp[0]
        self.fingerprint = _decode_fingerprint(r_comp[1], validate)
        self.digest      = r_comp[2]
        self.address     = r_comp[5]
        self.or_port     = int(r_comp[6])
        self.dir_port    = None if r_comp[7] == '0' else int(r_comp[7])
        
        try:
          published = "%s %s" % (r_comp[3], r_comp[4])
          self.publication = datetime.datetime.strptime(published, "%Y-%m-%d %H:%M:%S")
        except ValueError:
          if validate:
            raise ValueError("Publication time time wasn't parseable: %s" % line)
      elif keyword == 's':
        # "s" Flags
        # s Named Running Stable Valid
        
        self.flags = value.split(" ")
      elif keyword == 'v':
        # "v" version
        # v Tor 0.2.2.35
        #
        # The spec says that if this starts with "Tor " then what follows is a
        # tor version. If not then it has "upgraded to a more sophisticated
        # protocol versioning system".
        
        self.version_line = value
        
        if value.startswith("Tor "):
          try:
            self.version = stem.version.Version(value[4:])
          except ValueError, exc:
            if validate:
              raise ValueError("Router status entry has a malformed tor version (%s): %s" % (exc, line))
      elif keyword == 'w':
        # "w" "Bandwidth=" INT ["Measured=" INT]
        # w Bandwidth=7980
        
        w_comp = value.split(" ")
        
        if len(w_comp) < 1:
          if not validate: continue
          raise ValueError("Router status entry's 'w' line is blank: %s" % line)
        elif not w_comp[0].startswith("Bandwidth="):
          if not validate: continue
          raise ValueError("Router status entry's 'w' line needs to start with a 'Bandwidth=' entry: %s" % line)
        
        for w_entry in w_comp:
          w_key, w_value = w_entry.split('=', 1)
          
          if w_key == "Bandwidth":
            if not w_value.isdigit():
              if not validate: continue
              raise ValueError("Router status entry's 'Bandwidth=' entry needs to have a numeric value: %s" % line)
            
            self.bandwidth = int(w_value)
          elif w_key == "Measured":
            if not w_value.isdigit():
              if not validate: continue
              raise ValueError("Router status entry's 'Measured=' entry needs to have a numeric value: %s" % line)
            
            self.measured = int(w_value)
          else:
            self.unrecognized_bandwidth_entries.append(w_entry)
      elif keyword == 'p':
        # "p" ("accept" / "reject") PortList
        # p reject 1-65535
        # p accept 80,110,143,443,993,995,6660-6669,6697,7000-7001
        
        try:
          self.exit_policy = stem.exit_policy.MicrodescriptorExitPolicy(value)
        except ValueError, exc:
          if not validate: continue
          raise ValueError("Router status entry's exit policy is malformed (%s): %s" % (exc, line))
      elif keyword == 'm':
        # "m" methods 1*(algorithm "=" digest)
        # m 8,9,10,11,12 sha256=g1vx9si329muxV3tquWIXXySNOIwRGMeAESKs/v4DWs
        
        m_comp = value.split(" ")
        
        if self.document.vote_status != "vote":
          if not validate: continue
          raise ValueError("Router status entry's 'm' line should only appear in votes (appeared in a %s): %s" % (self.document.vote_status, line))
        elif len(m_comp) < 1:
          if not validate: continue
          raise ValueError("Router status entry's 'm' line needs to start with a series of methods: %s" % line)
          
        try:
          methods = [int(entry) for entry in m_comp[0].split(",")]
        except ValueError:
          if not validate: continue
          raise ValueError("Router status entry's microdescriptor methods should be a series of comma separated integers: %s" % line)
        
        hashes = {}
        
        for entry in m_comp[1:]:
          if not '=' in entry:
            if not validate: continue
            raise ValueError("Router status entry's can only have a series of 'algorithm=digest' mappings after the methods: %s" % line)
          
          hash_name, digest = entry.split('=', 1)
          hashes[hash_name] = digest
        
        if self.microdescriptor_hashes is None:
          self.microdescriptor_hashes = []
        
        self.microdescriptor_hashes.append((methods, hashes))
      else:
        self.unrecognized_lines.append(line)
  
  def get_unrecognized_lines(self):
    """
    Provides any unrecognized lines.
    
    :returns: list of unrecognized lines
    """
    
    return self.unrecognized_lines

class MicrodescriptorConsensus(NetworkStatusDocument):
  """
  A v3 microdescriptor consensus.
  
  :var bool validated: **\*** whether the document is validated
  :var str network_status_version: **\*** a document format version. For v3 microdescriptor consensuses this is "3 microdesc"
  :var str vote_status: **\*** status of the vote (is "consensus")
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
  :var list directory_authorities: **\*** list of DirectoryAuthority objects that have generated this document
  :var dict bandwidth_weights: **~** dict of weight(str) => value(int) mappings
  :var list directory_signatures: **\*** list of signatures this document has
  
  | **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  | **~** attribute appears only in consensuses
  """
  
  def _get_router_type(self):
    return RouterMicrodescriptor
  
  def _validate_network_status_version(self):
    return self.network_status_version == "3 microdesc"

class RouterMicrodescriptor(RouterStatusEntry):
  """
  Router microdescriptor object. Parses and stores router information in a router
  microdescriptor from a v3 microdescriptor consensus.
  
  :var MicrodescriptorConsensus document: **\*** document this descriptor came from
  
  :var str nickname: **\*** router's nickname
  :var str fingerprint: **\*** router's fingerprint
  :var datetime publication: **\*** router's publication
  :var str ip: **\*** router's IP address
  :var int or_port: **\*** router's ORPort
  :var int dir_port: **\*** router's DirPort
  
  :var list flags: **\*** list of status flags
  
  :var :class:`stem.version.Version`,str version: Version of the Tor protocol this router is running
  
  :var int bandwidth: router's claimed bandwidth
  :var int measured_bandwidth: router's measured bandwidth
  
  :var str digest: base64 of the hash of the router's microdescriptor with trailing =s omitted
  
  | **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  """
  
  def __init__(self, raw_contents, document, validate = True):
    """
    Parse a router descriptor in a v3 microdescriptor consensus and provide a new
    RouterMicrodescriptor object.
    
    :param str raw_content: router descriptor content to be parsed
    :param MicrodescriptorConsensus document: document this descriptor came from
    :param bool validate: whether the router descriptor should be validated
    
    :raises: ValueError if the descriptor data is invalid
    """
    
    super(RouterMicrodescriptor, self).__init__(raw_contents, document, validate)
    
    self.document = document
  
  def _parse(self, raw_content, validate):
    """
    :param dict raw_content: router descriptor contents to be parsed
    :param bool validate: checks the validity of descriptor content if True
    
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
      self.nickname, self.fingerprint = values[0], _decode_fingerprint(values[1], validate)
      self.publication = _strptime(" ".join((values[2], values[3])), validate)
      self.ip, self.or_port, self.dir_port = values[4], int(values[5]), int(values[6])
      if self.dir_port == 0: self.dir_port = None
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
      
      elif peek_check_kw("m"):
        # microdescriptor hashes
        self.digest = _read_keyword_line("m", content, validate, True)
      
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

def _get_entries(content, validate, expected_first_keyword = None):
  """
  Provides the {keyword => [values...]} mappings for the given content.
  
  :param str content: descriptor content
  :param bool validate: checks validity if True
  :param str expected_first_keyword: validates that this is the first keyword
  
  :returns: dict with the mapping of keywords to their values
  
  :raises: ValueError if a validity check fails
  """
  
  entries = {}
  
  for line in content.split("\n"):
    # empty lines are allowed
    if not line: continue
    
    line_match = stem.descriptor.KEYWORD_LINE.match(line)
    
    if not line_match:
      if not validate: continue
      raise ValueError("Line contains invalid characters: %s" % line)
    
    keyword, value = line_match.groups()
    if value is None: value = ''
    
    if expected_first_keyword != None:
      if validate and expected_first_keyword != keyword:
        raise ValueError("Expected to start with a '%s' line:\n%s" % (expected_first_keyword, content))
      
      expected_first_keyword = None
    
    entries.setdefault(keyword, []).append(value)
  
  return entries

def _decode_fingerprint(identity, validate):
  """
  Decodes the 'identity' value found in consensuses into the more common hex
  encoding of the relay's fingerprint. For example...
  
  ::
  
    >>> _decode_fingerprint('p1aag7VwarGxqctS7/fS0y5FU+s')
    'A7569A83B5706AB1B1A9CB52EFF7D2D32E4553EB'
  
  :param str identity: encoded fingerprint from the consensus
  :param bool validate: checks validity if True
  
  :returns: str with the uppercase hex encoding of the relay's fingerprint
  
  :raises: ValueError if the result isn't a valid fingerprint
  """
  
  # trailing equal signs were stripped from the identity
  missing_padding = 28 - len(identity)
  identity += "=" * missing_padding
  
  fingerprint = ""
  for char in base64.b64decode(identity):
    # Individual characters are either standard ascii or hex encoded, and each
    # represent two hex digits. For instnace...
    #
    # >>> ord('\n')
    # 10
    # >>> hex(10)
    # '0xa'
    # >>> '0xa'[2:].zfill(2).upper()
    # '0A'
    
    fingerprint += hex(ord(char))[2:].zfill(2).upper()
  
  if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
    if validate:
      raise ValueError("Decoded '%s' to be '%s', which isn't a valid fingerprint" % (identity, fingerprint))
    else:
      return None
  
  return fingerprint

