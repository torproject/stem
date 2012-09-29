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
import collections

import stem.util.enum

KEYWORD_CHAR    = "a-zA-Z0-9-"
WHITESPACE      = " \t"
KEYWORD_LINE    = re.compile("^([%s]+)(?:[%s]+(.*))?$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_START = re.compile("^-----BEGIN ([%s%s]+)-----$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END   = "-----END %s-----"

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
  elif filename == "cached-microdesc-consensus":
    file_parser = lambda f: stem.descriptor.networkstatus.parse_file(f, True, True)
  else:
    # Metrics descriptor handling
    first_line, desc = descriptor_file.readline().strip(), None
    metrics_header_match = re.match("^@type (\S+) (\d+).(\d+)$", first_line)
    
    if metrics_header_match:
      desc_type, major_version, minor_version = metrics_header_match.groups()
      file_parser = lambda f: _parse_metrics_file(desc_type, int(major_version), int(minor_version), f)
  
  if file_parser:
    for desc in file_parser(descriptor_file):
      desc._set_path(path)
      yield desc
    
    return
  
  # Not recognized as a descriptor file.
  
  raise TypeError("Unable to determine the descriptor's type. filename: '%s', first line: '%s'" % (filename, first_line))

def _parse_metrics_file(descriptor_type, major_version, minor_version, descriptor_file):
  # Parses descriptor files from metrics, yielding individual descriptors. This
  # throws a TypeError if the descriptor_type or version isn't recognized.
  import stem.descriptor.server_descriptor
  import stem.descriptor.extrainfo_descriptor
  import stem.descriptor.networkstatus
  
  if descriptor_type == "server-descriptor" and major_version == 1:
    yield stem.descriptor.server_descriptor.RelayDescriptor(descriptor_file.read())
  elif descriptor_type == "bridge-server-descriptor" and major_version == 1:
    yield stem.descriptor.server_descriptor.BridgeDescriptor(descriptor_file.read())
  elif descriptor_type == "extra-info" and major_version == 1:
    yield stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor(descriptor_file.read())
  elif descriptor_type == "bridge-extra-info" and major_version == 1:
    # version 1.1 introduced a 'transport' field...
    # https://trac.torproject.org/6257
    
    yield stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor(descriptor_file.read())
  elif descriptor_type in ("network-status-consensus-3", "network-status-vote-3") and major_version == 1:
    for desc in stem.descriptor.networkstatus.parse_file(descriptor_file):
      yield desc
  elif descriptor_type == "network-status-microdesc-consensus-3" and major_version == 1:
    for desc in stem.descriptor.networkstatus.parse_file(descriptor_file, is_microdescriptor = True):
      yield desc
  else:
    raise TypeError("Unrecognized metrics descriptor format. type: '%s', version: '%i.%i'" % (descriptor_type, major_version, minor_version))

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

def _peek_line(descriptor_file):
  """
  Returns the line at the current offset of descriptor_file.
  
  :param file descriptor_file: file with the descriptor content
  
  :returns: line at the current offset of descriptor_file
  """
  
  last_position = descriptor_file.tell()
  line = descriptor_file.readline()
  descriptor_file.seek(last_position)
  
  return line

def _peek_keyword(descriptor_file):
  """
  Returns the keyword at the current offset of descriptor_file. Respects the
  "opt" keyword and returns the next keyword instead.
  
  :param file descriptor_file: file with the descriptor content
  
  :returns: keyword at the current offset of descriptor_file
  """
  
  line = _peek_line(descriptor_file)
  
  if line.startswith("opt "):
    line = line[4:]
  if not line: return None
  
  return line.split(" ", 1)[0].rstrip("\n")

def _read_keyword_line(keyword, descriptor_file, validate = True, optional = False):
  """
  Returns the rest of the line if the first keyword matches the given keyword. If
  it doesn't, a ValueError is raised if optional and validate are True, if
  not, None is returned.
  
  Respects the opt keyword and returns the next keyword if the first is "opt".
  
  :param str keyword: keyword the line must begin with
  :param bool descriptor_file: file/file-like object containing descriptor data
  :param bool validate: validation is enabled
  :param bool optional: if the current line must begin with the given keyword
  
  :returns: the text after the keyword if the keyword matches the one provided, otherwise returns None or raises an exception
  
  :raises: ValueError if a non-optional keyword doesn't match when validation is enabled
  """
  
  line = _peek_line(descriptor_file)
  if not line:
    if not optional and validate:
      raise ValueError("Unexpected end of document")
    return None
  
  if line.startswith("opt "):
    line = line[4:]
  if re.match("^" + re.escape(keyword) + "($| )", line):
    descriptor_file.readline()
    return line[len(keyword):].strip()
  elif not optional and validate:
    raise ValueError("Error parsing network status document: Expected %s, received: %s" % (keyword, line))
  else: return None

def _read_keyword_line_str(keyword, lines, validate = True, optional = False):
  """
  Returns the rest of the line if the first keyword matches the given keyword. If
  it doesn't, a ValueError is raised if optional and validate are True, if
  not, None is returned.
  
  Respects the opt keyword and returns the next keyword if the first is "opt".
  
  :param str keyword: keyword the line must begin with
  :param list lines: list of strings to be read from
  :param bool validate: validation is enabled
  :param bool optional: if the current line must begin with the given keyword
  
  :returns: the text after the keyword if the keyword matches the one provided, otherwise returns None or raises an exception
  
  :raises: ValueError if a non-optional keyword doesn't match when validation is enabled
  """
  
  if not lines:
    if not optional and validate:
      raise ValueError("Unexpected end of document")
    return
  
  if lines[0].startswith("opt "):
    line = line[4:]
  if line_matches_keyword(keyword, lines[0]):
    line = lines.pop(0)
    
    return line[len(keyword):].strip()
  elif not optional and validate:
    raise ValueError("Error parsing network status document: Expected %s, received: %s" % (keyword, lines[0]))
  else: return None

def _read_until_keywords(keywords, descriptor_file, inclusive = False, ignore_first = False, skip = False, end_position = None):
  """
  Reads from the descriptor file until we get to one of the given keywords or reach the
  end of the file.
  
  :param str,list keywords: keyword(s) we want to read until
  :param file descriptor_file: file with the descriptor content
  :param bool inclusive: includes the line with the keyword if True
  :param bool ignore_first: doesn't check if the first line read has one of the given keywords
  :param bool skip: skips buffering content, returning None
  :param int end_position: end if we reach this point in the file
  
  :returns: list with the lines until we find one of the keywords
  """
  
  content = None if skip else []
  if type(keywords) == str: keywords = (keywords,)
  
  if ignore_first:
    first_line = descriptor_file.readline()
    
    if content != None and first_line != None:
      content.append(first_line)
  
  while True:
    last_position = descriptor_file.tell()
    
    if end_position and last_position >= end_position:
      break
    
    line = descriptor_file.readline()
    if not line: break # EOF
    
    line_match = KEYWORD_LINE.match(line)
    
    if not line_match:
      # no spaces or tabs in the line
      line_keyword = line.strip()
    else:
      line_keyword = line_match.groups()[0]
    
    if line_keyword in keywords:
      if not inclusive:
        descriptor_file.seek(last_position)
      elif content != None:
        content.append(line)
      
      break
    elif content != None:
      content.append(line)
  
  return content

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
    end_line = PGP_BLOCK_END % block_type
    
    while True:
      if not remaining_contents:
        raise ValueError("Unterminated pgp style block (looking for '%s'):\n%s" % (end_line, "\n".join(block_lines)))
      
      line = remaining_contents.pop(0)
      block_lines.append(line)
      
      if line == end_line:
        return "\n".join(block_lines)
  else:
    return None

def _get_descriptor_components(raw_contents, validate, extra_keywords = ()):
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
    
    * **entries (collections.OrderedDict)** - keyword => (value, pgp key) entries
    * **first_keyword (str)** - keyword of the first line
    * **last_keyword (str)**  - keyword of the last line
    * **extra_entries (list)** - lines containing entries matching extra_keywords
  """
  
  entries = collections.OrderedDict()
  first_keyword = None
  last_keyword = None
  extra_entries = [] # entries with a keyword in extra_keywords
  remaining_lines = raw_contents.split("\n")
  
  while remaining_lines:
    line = remaining_lines.pop(0)
    
    # V2 network status documents explicitely can contain blank lines...
    #
    #   "Implementations MAY insert blank lines for clarity between sections;
    #   these blank lines are ignored."
    #
    # ... and server descriptors end with an extra newline. But other documents
    # don't say how blank lines should be handled so globally ignoring them.
    
    if not line: continue
    
    # Some lines have an 'opt ' for backward compatability. They should be
    # ignored. This prefix is being removed in...
    # https://trac.torproject.org/projects/tor/ticket/5124
    
    if line.startswith("opt "): line = line[4:]
    
    line_match = KEYWORD_LINE.match(line)
    
    if not line_match:
      if not validate: continue
      raise ValueError("Line contains invalid characters: %s" % line)
    
    keyword, value = line_match.groups()
    if value is None: value = ''
    
    if not first_keyword: first_keyword = keyword
    last_keyword = keyword
    
    try:
      block_contents = _get_pseudo_pgp_block(remaining_lines)
    except ValueError, exc:
      if not validate: continue
      raise exc
    
    if keyword in extra_keywords:
      extra_entries.append("%s %s" % (keyword, value))
    else:
      entries.setdefault(keyword, []).append((value, block_contents))
  
  return entries, first_keyword, last_keyword, extra_entries

def _strptime(string, validate = True, optional = False):
  try:
    return datetime.datetime.strptime(string, "%Y-%m-%d %H:%M:%S")
  except ValueError, exc:
    if validate or not optional: raise exc
    else: return None

def line_matches_keyword(keyword, line):
  return re.search("^(opt )?" + re.escape(keyword) + "($| )", line)

