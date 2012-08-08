"""
Package for parsing and processing descriptor data.

**Module Overview:**

::

  parse_file - Iterates over the descriptors in a file.
  Descriptor - Common parent for all descriptor file types.
    |- get_path - location of the descriptor on disk if it came from a file
    |- get_unrecognized_lines - unparsed descriptor content
    +- __str__ - string that the descriptor was made from
"""

__all__ = [
  "export",
  "reader",
  "extrainfo_descriptor",
  "server_descriptor",
  "networkstatus",
  "parse_file",
  "Descriptor",
]

import os
import re
import datetime

KEYWORD_CHAR    = "a-zA-Z0-9-"
WHITESPACE      = " \t"
KEYWORD_LINE    = re.compile("^([%s]+)[%s]*(.*)$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_START = re.compile("^-----BEGIN ([%s%s]+)-----$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END   = "-----END %s-----"

def parse_file(path, descriptor_file):
  """
  Provides an iterator for the descriptors within a given file.
  
  :param str path: absolute path to the file's location on disk
  :param file descriptor_file: opened file with the descriptor contents
  
  :returns: iterator for :class:`stem.descriptor.Descriptor` instances in the file
  
  :raises:
    * TypeError if we can't match the contents of the file to a descriptor type
    * IOError if unable to read from the descriptor_file
  """
  
  import stem.descriptor.server_descriptor
  import stem.descriptor.extrainfo_descriptor
  import stem.descriptor.networkstatus
  
  # The tor descriptor specifications do not provide a reliable method for
  # identifying a descriptor file's type and version so we need to guess
  # based on its filename. Metrics descriptors, however, can be identified
  # by an annotation on their first line...
  # https://trac.torproject.org/5651
  
  # Cached descriptor handling. These contain mulitple descriptors per file.
  
  filename, file_parser = os.path.basename(path), None
  
  if filename == "cached-descriptors":
    file_parser = stem.descriptor.server_descriptor.parse_file
  elif filename == "cached-extrainfo":
    file_parser = stem.descriptor.extrainfo_descriptor.parse_file
  elif filename == "cached-consensus":
    file_parser = stem.descriptor.networkstatus.parse_file
  
  if file_parser:
    for desc in file_parser(descriptor_file):
      desc._set_path(path)
      yield desc
    
    return
  
  # Metrics descriptor handling. These contain a single descriptor per file.
  
  first_line, desc = descriptor_file.readline().strip(), None
  metrics_header_match = re.match("^@type (\S+) (\d+).(\d+)$", first_line)
  
  if metrics_header_match:
    # still doesn't necessarily mean that this is a descriptor, check if the
    # header contents are recognized
    
    desc_type, major_version, minor_version = metrics_header_match.groups()
    major_version, minor_version = int(major_version), int(minor_version)
    
    if desc_type == "server-descriptor" and major_version == 1:
      desc = stem.descriptor.server_descriptor.RelayDescriptor(descriptor_file.read())
    elif desc_type == "bridge-server-descriptor" and major_version == 1:
      desc = stem.descriptor.server_descriptor.BridgeDescriptor(descriptor_file.read())
    elif desc_type == "extra-info" and major_version == 1:
      desc = stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor(descriptor_file.read())
    elif desc_type == "bridge-extra-info" and major_version == 1:
      # version 1.1 introduced a 'transport' field...
      # https://trac.torproject.org/6257
      
      desc = stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor(descriptor_file.read())
    elif desc_type in ("network-status-consensus-3", "network-status-vote-3") and major_version == 1:
      desc = stem.descriptor.networkstatus.NetworkStatusDocument(descriptor_file.read())
      for desc in desc.router_descriptors:
        desc._set_path(path)
        yield desc
      return
  
  if desc:
    desc._set_path(path)
    yield desc
    return
  
  # Not recognized as a descriptor file.
  
  raise TypeError("Unable to determine the descriptor's type. filename: '%s', first line: '%s'" % (filename, first_line))

class Descriptor(object):
  """
  Common parent for all types of descriptors.
  """
  
  def __init__(self, contents):
    self._path = None
    self._raw_contents = contents
  
  def get_path(self):
    """
    Provides the absolute path that we loaded this descriptor from.
    
    :returns: str with the absolute path of the descriptor source
    """
    
    return self._path
  
  def get_unrecognized_lines(self):
    """
    Provides a list of lines that were either ignored or had data that we did
    not know how to process. This is most common due to new descriptor fields
    that this library does not yet know how to process. Patches welcome!
    
    :returns: list of lines of unrecognized content
    """
    
    raise NotImplementedError
  
  def _set_path(self, path):
    self._path = path
  
  def __str__(self):
    return self._raw_contents

def _peek_keyword(descriptor_file):
  """
  Returns the keyword at the current offset of descriptor_file. Respects the
  "opt" keyword and returns the next keyword instead.
  
  :param file descriptor_file: file with the descriptor content
  
  :returns: keyword at the current offset of descriptor_file
  """
  
  last_position = descriptor_file.tell()
  line = descriptor_file.readline()
  if not line: return None
  
  if " " in line:
    keyword = line.split(" ", 1)[0]
    if keyword == "opt":
        keyword = line.split(" ", 2)[1]
  else: keyword = line.strip()
  
  descriptor_file.seek(last_position)
  
  return keyword

def _read_until_keywords(keywords, descriptor_file, inclusive = False, ignore_first = False):
  """
  Reads from the descriptor file until we get to one of the given keywords or reach the
  end of the file.
  
  :param str,list keywords: keyword(s) we want to read until
  :param file descriptor_file: file with the descriptor content
  :param bool inclusive: includes the line with the keyword if True
  :param bool ignore_first: doesn't check if the first line read has one of the given keywords
  
  :returns: list with the lines until we find one of the keywords
  """
  
  content = []
  if type(keywords) == str: keywords = (keywords,)
  
  if ignore_first:
    content.append(descriptor_file.readline())
    if content == [None]: return []
  
  while True:
    last_position = descriptor_file.tell()
    line = descriptor_file.readline()
    if not line: break # EOF
    
    if " " in line: line_keyword = line.split(" ", 1)[0]
    else: line_keyword = line.strip()
    
    if line_keyword in keywords:
      if inclusive: content.append(line)
      else: descriptor_file.seek(last_position)
      
      break
    else:
      content.append(line)
  
  return content

def _skip_until_keywords(keywords, descriptor_file, inclusive = False):
  """
  Reads and discards lines of data from the descriptor file until we get to one
  of the given keywords or reach the end of the file.
  
  :param str,list keywords: keyword(s) we want to skip until
  :param file descriptor_file: file with the descriptor content
  :param bool inclusive: includes the line with the keyword if True
  
  :returns: descriptor_file with the new offset
  """
  
  if type(keywords) == str: keywords = (keywords,)
  
  while True:
    last_position = descriptor_file.tell()
    line = descriptor_file.readline()
    if not line: break # EOF
    
    if " " in line: line_keyword = line.split(" ", 1)[0]
    else: line_keyword = line.strip()
    
    if line_keyword in keywords:
      if not inclusive: descriptor_file.seek(last_position)
      
      break
  
  return descriptor_file

def _get_pseudo_pgp_block(remaining_contents):
  """
  Checks if given contents begins with a pseudo-Open-PGP-style block and, if
  so, pops it off and provides it back to the caller.
  
  :param list remaining_contents: lines to be checked for a public key block
  
  :returns: str with the armor wrapped contents or None if it doesn't exist
  
  :raises: ValueError if the contents starts with a key block but it's malformed (for instance, if it lacks an ending line)
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

def _get_descriptor_components(raw_contents, validate, extra_keywords):
  """
  Initial breakup of the server descriptor contents to make parsing easier.
  
  A descriptor contains a series of 'keyword lines' which are simply a keyword
  followed by an optional value. Lines can also be followed by a signature
  block.
  
  To get a sublisting with just certain keywords use extra_keywords. This can
  be useful if we care about their relative ordering with respect to each
  other. For instance, we care about the ordering of 'accept' and 'reject'
  entries because this influences the resulting exit policy, but for everything
  else in server descriptors the order does not matter.
  
  :param str raw_contents: descriptor content provided by the relay
  :param bool validate: checks the validity of the descriptor's content if True, skips these checks otherwise
  :param list extra_keywords: entity keywords to put into a separate listing with ordering intact
  
  :returns:
    tuple with the following attributes...
    
    * **entries (dict)** - keyword => (value, pgp key) entries
    * **first_keyword (str)** - keyword of the first line
    * **last_keyword (str)**  - keyword of the last line
    * **extra_entries (list)** - lines containing entries matching extra_keywords
  """
  
  entries = {}
  first_keyword = None
  last_keyword = None
  extra_entries = [] # entries with a keyword in extra_keywords
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
    
    if keyword in extra_keywords:
      extra_entries.append("%s %s" % (keyword, value))
    elif keyword in entries:
      entries[keyword].append((value, block_contents))
    else:
      entries[keyword] = [(value, block_contents)]
  
  return entries, first_keyword, last_keyword, extra_entries

def _strptime(string, validate = True, optional = False):
  try:
    return datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
  except ValueError, exc:
    if validate or not optional: raise exc

class DescriptorParser:
  """
  Helper class to parse documents.
  
  :var str line: current line to be being parsed
  :var list lines: list of remaining lines to be parsed
  """
  
  def __init__(self, raw_content, validate):
    """
    Create a new DocumentParser.
    
    :param str raw_content: content to be parsed
    :param bool validate: if False, treats every keyword line as optional
    """
    
    self._raw_content = raw_content
    self.lines = raw_content.split("\n")
    self.validate = validate
    self.line = self.lines.pop(0)
    
  def peek_keyword(self):
    """
    Returns the first keyword in the next line. Respects the opt keyword and
    returns the actual keyword if the first is "opt".
    
    :returns: the first keyword of the next line
    """
    
    if self.line:
      if self.line.startswith("opt "):
        return self.line.split(" ")[1]
      return self.line.split(" ")[0]
  
  def read_keyword_line(self, keyword, optional = False):
    """
    Returns the first keyword in the next line it matches the given keyword.
    
    If it doesn't match, a ValueError is raised if optional is True and if the
    DocumentParser was created with validation enabled. If not, None is returned.
    
    Respects the opt keyword and returns the next keyword if the first is "opt".
    
    :param str keyword: keyword the line must begin with
    :param bool optional: If the current line must begin with the given keyword
    
    :returns: the text after the keyword if the keyword matches the one provided, otherwise returns None or raises an exception
    
    :raises: ValueError if a non-optional keyword doesn't match when validation is enabled
    """
    
    keyword_regex = re.compile("(opt )?" + re.escape(keyword) + "($| )")
    
    if not self.line:
      if not optional and self.validate:
        raise ValueError("Unexpected end of document")
      return
    
    if keyword_regex.match(self.line):
      line = self.read_line()
      
      if line == "opt " + keyword or line == keyword: return ""
      elif line.startswith("opt "): return line.split(" ", 2)[2]
      else: return line.split(" ", 1)[1]
    elif self.line.startswith("opt"):
      # if this is something new we don't recognize
      # ignore it and go to the next line
      self.read_line()
      return self.read_keyword_line(self, keyword, optional)
    elif not optional and self.validate:
      raise ValueError("Error parsing network status document: Expected %s, received: %s" % (keyword, self.line))
  
  def read_line(self):
    """
    Returns the current line and shifts the parser to the next line.
    
    :returns: the current line if it exists, None otherwise
    """
    
    if self.line:
      try: tmp, self.line = self.line, self.lines.pop(0)
      except IndexError: tmp, self.line = self.line, None
      
      return tmp
    elif not optional and self.validate:
      raise ValueError("Unexpected end of document")
  
  def read_block(self, keyword):
    """
    Returns a keyword block that begins with "-----BEGIN keyword-----\\n" and
    ends with "-----END keyword-----\\n".
    
    :param str keyword: keyword block that must be read
    
    :returns: the data in the keyword block
    """
    
    lines = []
    
    if self.line == "-----BEGIN " + keyword + "-----":
      self.read_line()
      while self.line != "-----END " + keyword + "-----":
        lines.append(self.read_line())
    
    self.read_line() # pop out the END line
    
    return "\n".join(lines)
  
  def read_until(self, terminals = []):
    """
    Returns the data in the parser until a line that begins with one of the keywords in terminals are found.
    
    :param list terminals: list of strings at which we should stop reading and return the data
    
    :returns: the current line if it exists, None otherwise
    """
    
    if self.line == None: return
    lines = [self.read_line()]
    while self.line and not self.line.split(" ")[0] in terminals:
      lines.append(self.line)
      self.read_line()
    
    return "\n".join(lines)
  
  def remaining(self):
    """
    Returns the data remaining in the parser.
    
    :returns: all a list of all unparsed lines
    """
    
    if self.line:
      lines, self.lines = self.lines, []
      lines.insert(0, self.line)
      self.line = None
      return lines
    else:
      return []

class KeyCertificate(Descriptor):
  """
  Directory key certificate.
  
  :var str key_certificate_version: **\*** version of the key certificate (Should be "3")
  :var str ip: IP address on which the directory authority is listening
  :var int port: port on which the directory authority is listening
  :var str fingerprint: **\*** hex encoded fingerprint of the authority's identity key
  :var str identity_key: **\*** long term authority identity key
  :var datetime published: **\*** time (in GMT) when this document & the key were last generated
  :var str expires: **\*** time (in GMT) after which this key becomes invalid
  :var str signing_key: **\*** directory server's public signing key
  :var str crosscert: signature made using certificate's signing key
  :var str certification: **\*** signature of this key certificate signed with the identity key
  
  **\*** attribute is either required when we're parsed with validation or has a default value, others are left as None if undefined
  """
  
  def __init__(self, raw_content, validate = True):
    """
    Parse a key certificate entry and provide a KeyCertificate object.
    
    :param str raw_content: raw key certificate information
    :param bool validate: True if the document is to be validated, False otherwise
    
    :raises: ValueError if the raw data is invalid
    """
    
    super(KeyCertificate, self).__init__(raw_content)
    self.key_certificate_version, self.ip, self.port = None, None, None
    self.fingerprint, self.identity_key, self.published = None, None, None
    self.expires, self.signing_key, self.crosscert = None, None, None
    self.certification = None
    parser = DescriptorParser(raw_content, validate)
    peek_check_kw = lambda keyword: keyword == parser.peek_keyword()
    seen_keywords = set()
    
    self.key_certificate_version = parser.read_keyword_line("dir-key-certificate-version")
    if validate and self.key_certificate_version != "3": raise ValueError("Unrecognized dir-key-certificate-version")
    
    def _read_keyword_line(keyword):
      if validate and keyword in seen_keywords:
        raise ValueError("Invalid key certificate: '%s' appears twice" % keyword)
      seen_keywords.add(keyword)
      return parser.read_keyword_line(keyword)
    
    while parser.line:
      if peek_check_kw("dir-address"):
        line = _read_keyword_line("dir-address")
        try:
          self.ip, self.port = line.rsplit(":", 1)
          self.port = int(self.port)
        except Exception:
          if validate: raise ValueError("Invalid dir-address line: %s" % line)
      
      elif peek_check_kw("fingerprint"):
        self.fingerprint = _read_keyword_line("fingerprint")
      
      elif peek_check_kw("dir-identity-key"):
        _read_keyword_line("dir-identity-key")
        self.identity_key = parser.read_block("RSA PUBLIC KEY")
      
      elif peek_check_kw("dir-key-published"):
        self.published = _strptime(_read_keyword_line("dir-key-published"))
      
      elif peek_check_kw("dir-key-expires"):
        self.expires = _strptime(_read_keyword_line("dir-key-expires"))
      
      elif peek_check_kw("dir-signing-key"):
        _read_keyword_line("dir-signing-key")
        self.signing_key = parser.read_block("RSA PUBLIC KEY")
      
      elif peek_check_kw("dir-key-crosscert"):
        _read_keyword_line("dir-key-crosscert")
        self.crosscert = parser.read_block("ID SIGNATURE")
      
      elif peek_check_kw("dir-key-certification"):
        _read_keyword_line("dir-key-certification")
        self.certification = parser.read_block("SIGNATURE")
        break
      
      elif validate:
        raise ValueError("Key certificate contains unrecognized lines: %s" % parser.line)
      
      else:
        # ignore unrecognized lines if we aren't validating
        self._unrecognized_lines.append(parser.read_line())
    
    self._unrecognized_lines = parser.remaining()
    if self._unrecognized_lines and validate:
      raise ValueError("Unrecognized trailing data in key certificate")
  
  def get_unrecognized_lines(self):
    """
    Returns any unrecognized lines.
    
    :returns: a list of unrecognized lines
    """
    
    return self._unrecognized_lines

