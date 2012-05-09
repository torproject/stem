"""
Parsing for Tor extra-info descriptors. These are published by relays whenever
their server descriptor is published and have a similar format. However, unlike
server descriptors these don't contain information that Tor clients require to
function and as such aren't fetched by default.

Defined in section 2.2 of the dir-spec, extra-info descriptors contain
interesting but non-vital information such as usage statistics. These documents
cannot be requested of bridges.

Extra-info descriptors are available from a few sources...

- if you have 'DownloadExtraInfo 1' in your torrc...
  - control port via 'GETINFO extra-info/digest/*' queries
  - the 'cached-extrainfo' file in tor's data directory
- tor metrics, at https://metrics.torproject.org/data.html
- directory authorities and mirrors via their DirPort

parse_file - Iterates over the extra-info descriptors in a file.
ExtraInfoDescriptor - Tor extra-info descriptor.
  +- get_unrecognized_lines - lines with unrecognized content
"""

import re
import datetime

import stem.descriptor

# relay descriptors must have exactly one of the following
REQUIRED_FIELDS = (
  "extra-info",
  "published",
  "router-signature",
)

# optional entries that can appear at most once
SINGLE_FIELDS = (
  "read-history",
  "write-history",
  "geoip-db-digest",
  "bridge-stats-end",
  "bridge-ips",
  "dirreq-stats-end",
  "dirreq-v2-ips",
  "dirreq-v3-ips",
  "dirreq-v2-reqs",
  "dirreq-v3-reqs",
  "dirreq-v2-share",
  "dirreq-v3-share",
  "dirreq-v2-resp",
  "dirreq-v3-resp",
  "dirreq-v2-direct-dl",
  "dirreq-v3-direct-dl",
  "dirreq-v2-tunneled-dl",
  "dirreq-v3-tunneled-dl",
  "dirreq-read-history",
  "dirreq-write-history",
  "entry-stats-end",
  "entry-ips",
  "cell-stats-end",
  "cell-processed-cells",
  "cell-queued-cells",
  "cell-time-in-queue",
  "cell-circuits-per-decile",
  "conn-bi-direct",
  "exit-stats-end",
  "exit-kibibytes-written",
  "exit-kibibytes-read",
  "exit-streams-opened",
)

FIRST_FIELD = "extra-info"
LAST_FIELD = "router-signature"

def parse_file(descriptor_file, validate = True):
  """
  Iterates over the extra-info descriptors in a file.
  
  Arguments:
    descriptor_file (file) - file with descriptor content
    validate (bool)        - checks the validity of the descriptor's content if
                             True, skips these checks otherwise
  
  Returns:
    iterator for ExtraInfoDescriptor instances in the file
  
  Raises:
    ValueError if the contents is malformed and validate is True
    IOError if the file can't be read
  """
  
  while True:
    extrainfo_content = stem.descriptor._read_until_keyword("router-signature", descriptor_file)
    
    # we've reached the 'router-signature', now include the pgp style block
    block_end_prefix = stem.descriptor.PGP_BLOCK_END.split(' ', 1)[0]
    extrainfo_content += stem.descriptor._read_until_keyword(block_end_prefix, descriptor_file, True)
    
    if extrainfo_content:
      yield ExtraInfoDescriptor("".join(extrainfo_content), validate)
    else: break # done parsing file

def _parse_timestamp_and_interval(keyword, content):
  """
  Parses a 'YYYY-MM-DD HH:MM:SS (NSEC s) *' entry.
  
  Arguments:
    keyword (str) - line's keyword
    content (str) - line content to be parsed
  
  Returns:
    tuple of the form...
    (timestamp (datetime), interval (int), remaining content (str))
  
  Raises:
    ValueError if the content is malformed
  """
  
  line = "%s %s" % (keyword, content)
  content_match = re.match("^(.*) \(([0-9]+) s\)( .*)?$", content)
  
  if not content_match:
    raise ValueError("Malformed %s line: %s" % (keyword, line))
  
  timestamp_str, interval, remainder = content_match.groups()
  if remainder: remainder = remainder[1:] # remove leading space
  
  if not interval.isdigit():
    raise ValueError("%s line's interval wasn't a number: %s" % (keyword, line))
  
  try:
    timestamp = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    return timestamp, int(interval), remainder
  except ValueError:
    raise ValueError("%s line's timestamp wasn't parseable: %s" % (keyword, line))

class ExtraInfoDescriptor(stem.descriptor.Descriptor):
  """
  Extra-info descriptor document.
  
  Attributes:
    nickname (str)           - relay's nickname (*)
    fingerprint (str)        - fourty hex digits that make up the relay's fingerprint (*)
    published (datetime.datetime) - time in GMT when the descriptor was generated (*)
    geoip_db_digest (str)    - sha1 of geoIP database file
    signature (str)          - signature for this extrainfo descriptor (*)
    
    read_history_line (str)  - bytes read for relayed traffic
    read_history_end (datetime.datetime) - end of the sampling interval
    read_history_interval (int) - seconds per interval
    read_history_values (list) - bytes read during each interval (*)
    
    write_history_line (str) - bytes written for relayed traffic
    write_history_end (datetime.datetime) - end of the sampling interval
    write_history_interval (int) - seconds per interval
    write_history_values (list) - bytes written during each interval (*)
    
    dir_read_history_line (str) - bytes read for directory mirroring
    dir_read_history_end (datetime.datetime) - end of the sampling interval
    dir_read_history_interval (int) - seconds per interval
    dir_read_history_values (list) - bytes read during each interval (*)
    
    dir_write_history_line (str) - bytes written for directory mirroring
    dir_write_history_end (datetime.datetime) - end of the sampling interval
    dir_write_history_interval (int) - seconds per interval
    dir_write_history_values (list) - bytes read during each interval (*)
    
    (*) required fields, others are left as None if undefined
  """
  
  def __init__(self, raw_contents, validate = True, annotations = None):
    """
    Extra-info descriptor constructor, created from a relay's extra-info
    content (as provided by "GETINFO extra-info/digest/*", cached contents, and
    metrics).
    
    By default this validates the descriptor's content as it's parsed. This
    validation can be disables to either improve performance or be accepting of
    malformed data.
    
    Arguments:
      raw_contents (str) - extra-info content provided by the relay
      validate (bool)    - checks the validity of the extra-info descriptor if
                           True, skips these checks otherwise
    
    Raises:
      ValueError if the contents is malformed and validate is True
    """
    
    stem.descriptor.Descriptor.__init__(self, raw_contents)
    
    self.nickname = None
    self.fingerprint = None
    self.published = None
    self.geoip_db_digest = None
    self.signature = None
    
    self.read_history_line = None
    self.read_history_end = None
    self.read_history_interval = None
    self.read_history_values = []
    
    self.write_history_line = None
    self.write_history_end = None
    self.write_history_interval = None
    self.write_history_values = []
    
    self.dir_read_history_line = None
    self.dir_read_history_end = None
    self.dir_read_history_interval = None
    self.dir_read_history_values = []
    
    self.dir_write_history_line = None
    self.dir_write_history_end = None
    self.dir_write_history_interval = None
    self.dir_write_history_values = []
    
    self._unrecognized_lines = []
    
    entries, first_keyword, last_keyword, _ = \
      stem.descriptor._get_descriptor_components(raw_contents, validate, ())
    
    if validate:
      for keyword in REQUIRED_FIELDS:
        if not keyword in entries:
          raise ValueError("Extra-info descriptor must have a '%s' entry" % keyword)
      
      for keyword in REQUIRED_FIELDS + SINGLE_FIELDS:
        if keyword in entries and len(entries[keyword]) > 1:
          raise ValueError("The '%s' entry can only appear once in an extra-info descriptor" % keyword)
      if not first_keyword == FIRST_FIELD:
        raise ValueError("Extra-info descriptor must start with a '%s' entry" % FIRST_FIELD)
      
      if not last_keyword == LAST_FIELD:
        raise ValueError("Descriptor must end with a '%s' entry" % LAST_FIELD)
    
    self._parse(entries, validate)
  
  def get_unrecognized_lines(self):
    return list(self._unrecognized_lines)
  
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
      
      if keyword == "extra-info":
        # "extra-info" Nickname Fingerprint
        extra_info_comp = value.split()
        
        if len(extra_info_comp) != 2:
          if not validate: continue
          raise ValueError("Extra-info line must have two values: %s" % line)
        
        if validate:
          if not stem.util.tor_tools.is_valid_nickname(extra_info_comp[0]):
            raise ValueError("Extra-info line entry isn't a valid nickname: %s" % extra_info_comp[0])
          elif not stem.util.tor_tools.is_valid_fingerprint(extra_info_comp[1]):
            raise ValueError("Tor relay fingerprints consist of fourty hex digits: %s" % extra_info_comp[1])
        
        self.nickname = extra_info_comp[0]
        self.fingerprint = extra_info_comp[1]
      elif keyword == "published":
        # "published" YYYY-MM-DD HH:MM:SS
        
        try:
          self.published = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        except ValueError:
          if validate:
            raise ValueError("Published line's time wasn't parseable: %s" % line)
      elif keyword in ("read-history", "write-history", "dirreq-read-history", "dirreq-write-history"):
        try:
          timestamp, interval, remainder = _parse_timestamp_and_interval(keyword, value)
          
          try:
            if remainder:
              history_values = [int(entry) for entry in remainder.split(",")]
            else:
              history_values = []
          except ValueError:
            raise ValueError("%s line has non-numeric values: %s" % (keyword, line))
          
          if keyword == "read-history":
            self.read_history_line = value
            self.read_history_end = timestamp
            self.read_history_interval = interval
            self.read_history_values = history_values
          elif keyword == "write-history":
            self.write_history_line = value
            self.write_history_end = timestamp
            self.write_history_interval = interval
            self.write_history_values = history_values
          elif keyword == "dirreq-read-history":
            self.dir_read_history_line = value
            self.dir_read_history_end = timestamp
            self.dir_read_history_interval = interval
            self.dir_read_history_values = history_values
          elif keyword == "dirreq-write-history":
            self.dir_write_history_line = value
            self.dir_write_history_end = timestamp
            self.dir_write_history_interval = interval
            self.dir_write_history_values = history_values
          else:
            # not gonna happen unless we change the main loop's conditional
            # without fixing this one
            raise ValueError("BUG: unrecognized keyword '%s'" % keyword)
        except ValueError, exc:
          if not validate: continue
          else: raise exc
      elif keyword == "router-signature":
        if validate and not block_contents:
          raise ValueError("Router signature line must be followed by a signature block: %s" % line)
        
        self.signature = block_contents
      else:
        self._unrecognized_lines.append(line)

