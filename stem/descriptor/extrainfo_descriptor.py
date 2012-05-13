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

DirResponses - known statuses for ExtraInfoDescriptor's dir_*_responses
  |- OK - network status requests that were answered
  |- NOT_ENOUGH_SIGS - network status wasn't signed by enough authorities
  |- UNAVAILABLE - requested network status was unavailable
  |- NOT_FOUND - requested network status was not found
  |- NOT_MODIFIED - network status unmodified since If-Modified-Since time
  +- BUSY - directory was busy

DirStats - known stats for ExtraInfoDescriptor's dir_*_direct_dl and dir_*_tunneled_dl
  |- COMPLETE - requests that completed successfully
  |- TIMEOUT - requests that didn't complete within a ten minute timeout
  |- RUNNING - requests still in procress when measurement's taken
  |- MIN - smallest rate at which a descriptor was downloaded in B/s
  |- MAX - largest rate at which a descriptor was downloaded in B/s
  |- D1-4 and D6-9 - rate of the slowest x/10 download rates in B/s
  |- Q1 and Q3 - rate of the slowest and fastest querter download rates in B/s
  +- MD - median download rate in B/s

parse_file - Iterates over the extra-info descriptors in a file.
ExtraInfoDescriptor - Tor extra-info descriptor.
  +- get_unrecognized_lines - lines with unrecognized content
"""

import re
import datetime

import stem.descriptor
import stem.util.enum

# known statuses for dirreq-v2-resp and dirreq-v3-resp...
DirResponses = stem.util.enum.Enum(
  ("OK", "ok"),
  ("NOT_ENOUGH_SIGS", "not-enough-sigs"),
  ("UNAVAILABLE", "unavailable"),
  ("NOT_FOUND", "not-found"),
  ("NOT_MODIFIED", "not-modified"),
  ("BUSY", "busy"),
)

# known stats for dirreq-v2/3-direct-dl and dirreq-v2/3-tunneled-dl...
dir_stats = ['complete', 'timeout', 'running', 'min', 'max', 'q1', 'q3', 'md']
dir_stats += ['d%i' % i for i in range(1, 5)]
dir_stats += ['d%i' % i for i in range(6, 10)]
DirStats = stem.util.enum.Enum(*[(stat.upper(), stat) for stat in dir_stats])

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
    nickname (str)        - relay's nickname (*)
    fingerprint (str)     - identity key fingerprint (*)
    published (datetime)  - time in GMT when this descriptor was made (*)
    geoip_db_digest (str) - sha1 of geoIP database file
    signature (str)       - signature for this extrainfo descriptor (*)
    
    Bytes read/written for relayed traffic:
      read_history_end (datetime) - end of the sampling interval
      read_history_interval (int) - seconds per interval
      read_history_values (list)  - bytes read during each interval
      
      write_history_end (datetime) - end of the sampling interval
      write_history_interval (int) - seconds per interval
      write_history_values (list)  - bytes written during each interval
    
    Cell relaying statistics:
      cell_stats_end (datetime) - end of the period when stats were gathered
      cell_stats_interval (int) - length in seconds of the interval
      cell_processed_cells (list) - measurement of processed cells per circuit
      cell_queued_cells (list) - measurement of queued cells per circuit
      cell_time_in_queue (list) - mean enqueued time in milliseconds for cells
      cell_circuits_per_decile (int) - mean number of circuits in a deciles
    
    Directory Mirror Attributes:
      dir_stats_end (datetime) - end of the period when stats were gathered
      dir_stats_interval (int) - length in seconds of the interval
      dir_v2_ips (dict) - mapping of locales to rounded count of requester ips
      dir_v3_ips (dict) - mapping of locales to rounded count of requester ips
      dir_v2_share (float) - percent of total directory traffic it expects to serve
      dir_v3_share (float) - percent of total directory traffic it expects to serve
      dir_v2_requests (dict) - mapping of locales to rounded count of requests
      dir_v3_requests (dict) - mapping of locales to rounded count of requests
      
      dir_v2_responses (dict) - mapping of DirResponses to their rounded count
      dir_v3_responses (dict) - mapping of DirResponses to their rounded count
      dir_v2_responses_unknown (dict) - mapping of unrecognized statuses to their count
      dir_v3_responses_unknown (dict) - mapping of unrecognized statuses to their count
      
      dir_v2_direct_dl (dict) - mapping of DirStats to measurement over DirPort
      dir_v3_direct_dl (dict) - mapping of DirStats to measurement over DirPort
      dir_v2_direct_dl_unknown (dict) - mapping of unrecognized stats to their measurement
      dir_v3_direct_dl_unknown (dict) - mapping of unrecognized stats to their measurement
      
      dir_v2_tunneled_dl (dict) - mapping of DirStats to measurement over ORPort
      dir_v3_tunneled_dl (dict) - mapping of DirStats to measurement over ORPort
      dir_v2_tunneled_dl_unknown (dict) - mapping of unrecognized stats to their measurement
      dir_v3_tunneled_dl_unknown (dict) - mapping of unrecognized stats to their measurement
      
      Bytes read/written for directory mirroring:
        dir_read_history_end (datetime) - end of the sampling interval
        dir_read_history_interval (int) - seconds per interval
        dir_read_history_values (list)  - bytes read during each interval
        
        dir_write_history_end (datetime) - end of the sampling interval
        dir_write_history_interval (int) - seconds per interval
        dir_write_history_values (list)  - bytes read during each interval
    
    Guard Attributes:
      entry_stats_end (datetime) - end of the period when stats were gathered
      entry_stats_interval (int) - length in seconds of the interval
      entry_ips (dict) - mapping of locales to rounded count of unique user ips
    
    Bridge Attributes:
      bridge_stats_end (datetime) - end of the period when stats were gathered
      bridge_stats_interval (int) - length in seconds of the interval
      bridge_ips (dict) - mapping of locales to rounded count of unique user ips
      geoip_start_time (datetime) - (deprecated) replaced by bridge_stats_end
      geoip_client_origins (dict) - (deprecated) replaced by bridge_ips
  
  (*) attribute is either required when we're parsed with validation or has a
      default value, others are left as None if undefined
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
    
    self.read_history_end = None
    self.read_history_interval = None
    self.read_history_values = None
    
    self.write_history_end = None
    self.write_history_interval = None
    self.write_history_values = None
    
    self.cell_stats_end = None
    self.cell_stats_interval = None
    self.cell_processed_cells = None
    self.cell_queued_cells = None
    self.cell_time_in_queue = None
    self.cell_circuits_per_decile = None
    
    self.dir_stats_end = None
    self.dir_stats_interval = None
    self.dir_v2_ips = None
    self.dir_v3_ips = None
    self.dir_v2_share = None
    self.dir_v3_share = None
    self.dir_v2_requests = None
    self.dir_v3_requests = None
    self.dir_v2_responses = None
    self.dir_v3_responses = None
    self.dir_v2_responses_unknown = None
    self.dir_v3_responses_unknown = None
    self.dir_v2_direct_dl = None
    self.dir_v3_direct_dl = None
    self.dir_v2_direct_dl_unknown = None
    self.dir_v3_direct_dl_unknown = None
    self.dir_v2_tunneled_dl = None
    self.dir_v3_tunneled_dl = None
    self.dir_v2_tunneled_dl_unknown = None
    self.dir_v3_tunneled_dl_unknown = None
    
    self.dir_read_history_end = None
    self.dir_read_history_interval = None
    self.dir_read_history_values = None
    
    self.dir_write_history_end = None
    self.dir_write_history_interval = None
    self.dir_write_history_values = None
    
    self.entry_stats_end = None
    self.entry_stats_interval = None
    self.entry_ips = None
    
    self.bridge_stats_end = None
    self.bridge_stats_interval = None
    self.bridge_ips = None
    self.geoip_start_time = None
    self.geoip_client_origins = None
    
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
        
        if len(extra_info_comp) < 2:
          if not validate: continue
          raise ValueError("Extra-info line must have two values: %s" % line)
        
        if validate:
          if not stem.util.tor_tools.is_valid_nickname(extra_info_comp[0]):
            raise ValueError("Extra-info line entry isn't a valid nickname: %s" % extra_info_comp[0])
          elif not stem.util.tor_tools.is_valid_fingerprint(extra_info_comp[1]):
            raise ValueError("Tor relay fingerprints consist of fourty hex digits: %s" % extra_info_comp[1])
        
        self.nickname = extra_info_comp[0]
        self.fingerprint = extra_info_comp[1]
      elif keyword == "geoip-db-digest":
        # "geoip-db-digest" Digest
        
        if validate and not re.match("^[0-9a-fA-F]{40}$", value):
          raise ValueError("Geoip digest line had an invalid sha1 digest: %s" % line)
        
        self.geoip_db_digest = value
      elif keyword == "cell-circuits-per-decile":
        # "cell-circuits-per-decile" num
        
        if not value.isdigit():
          if validate:
            raise ValueError("Non-numeric cell-circuits-per-decile value: %s" % line)
          else:
            continue
        
        stat = int(value)
        
        if validate and stat < 0:
          raise ValueError("Negative cell-circuits-per-decile value: %s" % line)
        
        self.cell_circuits_per_decile = stat
      elif keyword in ("dirreq-v2-resp", "dirreq-v3-resp", "dirreq-v2-direct-dl", "dirreq-v3-direct-dl", "dirreq-v2-tunneled-dl", "dirreq-v3-tunneled-dl"):
        recognized_counts = {}
        unrecognized_counts = {}
        
        is_response_stats = keyword in ("dirreq-v2-resp", "dirreq-v3-resp")
        key_set = DirResponses if is_response_stats else DirStats
        
        key_type = "STATUS" if is_response_stats else "STAT"
        error_msg = "%s lines should contain %s=COUNT mappings: %s" % (keyword, key_type, line)
        
        
        if value:
          for entry in value.split(","):
            if not "=" in entry:
              if validate: raise ValueError(error_msg)
              else: continue
            
            status, count = entry.split("=", 1)
            
            if count.isdigit():
              if status in key_set:
                recognized_counts[status] = int(count)
              else:
                unrecognized_counts[status] = int(count)
            elif validate:
              raise ValueError(error_msg)
        
        if keyword == "dirreq-v2-resp":
          self.dir_v2_responses = recognized_counts
          self.dir_v2_responses_unknown = unrecognized_counts
        elif keyword == "dirreq-v3-resp":
          self.dir_v3_responses = recognized_counts
          self.dir_v3_responses_unknown = unrecognized_counts
        elif keyword == "dirreq-v2-direct-dl":
          self.dir_v2_direct_dl = recognized_counts
          self.dir_v2_direct_dl_unknown = unrecognized_counts
        elif keyword == "dirreq-v3-direct-dl":
          self.dir_v3_direct_dl = recognized_counts
          self.dir_v3_direct_dl_unknown = unrecognized_counts
        elif keyword == "dirreq-v2-tunneled-dl":
          self.dir_v2_tunneled_dl = recognized_counts
          self.dir_v2_tunneled_dl_unknown = unrecognized_counts
        elif keyword == "dirreq-v3-tunneled-dl":
          self.dir_v3_tunneled_dl = recognized_counts
          self.dir_v3_tunneled_dl_unknown = unrecognized_counts
      elif keyword in ("dirreq-v2-share", "dirreq-v3-share"):
        # "<keyword>" num%
        
        try:
          if not value.endswith("%"): raise ValueError()
          percentage = float(value[:-1]) / 100
          
          if validate and (percentage > 1 or percentage < 0):
            raise ValueError()
          
          if keyword == "dirreq-v2-share":
            self.dir_v2_share = percentage
          elif keyword == "dirreq-v3-share":
            self.dir_v3_share = percentage
        except ValueError, exc:
          if validate:
            raise ValueError("Value can't be parsed as a percentage: %s" % line)
      elif keyword in ("cell-processed-cells", "cell-queued-cells", "cell-time-in-queue"):
        # "<keyword>" num,...,num
        
        entries = []
        
        if value:
          for entry in value.split(","):
            try:
              entries.append(float(entry))
            except ValueError:
              if validate: raise ValueError("Non-numeric entry in %s listing: %s" % (keyword, line))
        
        if keyword == "cell-processed-cells":
          self.cell_processed_cells = entries
        elif keyword == "cell-queued-cells":
          self.cell_queued_cells = entries
        elif keyword == "cell-time-in-queue":
          self.cell_time_in_queue = entries
      elif keyword in ("published", "geoip-start-time"):
        # "<keyword>" YYYY-MM-DD HH:MM:SS
        
        try:
          timestamp = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
          
          if keyword == "published":
            self.published = timestamp
          elif keyword == "geoip-start-time":
            self.geoip_start_time = timestamp
        except ValueError:
          if validate:
            raise ValueError("Timestamp on %s line wasn't parseable: %s" % (keyword, line))
      elif keyword in ("cell-stats-end", "entry-stats-end", "bridge-stats-end", "dirreq-stats-end"):
        # "<keyword>" YYYY-MM-DD HH:MM:SS (NSEC s)
        
        try:
          timestamp, interval, _ = _parse_timestamp_and_interval(keyword, value)
          
          if keyword == "cell-stats-end":
            self.cell_stats_end = timestamp
            self.cell_stats_interval = interval
          elif keyword == "entry-stats-end":
            self.entry_stats_end = timestamp
            self.entry_stats_interval = interval
          elif keyword == "bridge-stats-end":
            self.bridge_stats_end = timestamp
            self.bridge_stats_interval = interval
          elif keyword == "dirreq-stats-end":
            self.dir_stats_end = timestamp
            self.dir_stats_interval = interval
        except ValueError, exc:
          if validate: raise exc
      elif keyword in ("read-history", "write-history", "dirreq-read-history", "dirreq-write-history"):
        # "<keyword>" YYYY-MM-DD HH:MM:SS (NSEC s) NUM,NUM,NUM,NUM,NUM...
        try:
          timestamp, interval, remainder = _parse_timestamp_and_interval(keyword, value)
          history_values = []
          
          if remainder:
            try:
              history_values = [int(entry) for entry in remainder.split(",")]
            except ValueError:
              raise ValueError("%s line has non-numeric values: %s" % (keyword, line))
          
          if keyword == "read-history":
            self.read_history_end = timestamp
            self.read_history_interval = interval
            self.read_history_values = history_values
          elif keyword == "write-history":
            self.write_history_end = timestamp
            self.write_history_interval = interval
            self.write_history_values = history_values
          elif keyword == "dirreq-read-history":
            self.dir_read_history_end = timestamp
            self.dir_read_history_interval = interval
            self.dir_read_history_values = history_values
          elif keyword == "dirreq-write-history":
            self.dir_write_history_end = timestamp
            self.dir_write_history_interval = interval
            self.dir_write_history_values = history_values
        except ValueError, exc:
          if validate: raise exc
      elif keyword in ("dirreq-v2-ips", "dirreq-v3-ips", "dirreq-v2-reqs", "dirreq-v3-reqs", "geoip-client-origins", "entry-ips", "bridge-ips"):
        # "<keyword>" CC=N,CC=N,...
        #
        # The maxmind geoip (https://www.maxmind.com/app/iso3166) has numeric
        # locale codes for some special values, for instance...
        #   A1,"Anonymous Proxy"
        #   A2,"Satellite Provider"
        #   ??,"Unknown"
        
        locale_usage = {}
        error_msg = "Entries in %s line should only be CC=N entries: %s" % (keyword, line)
        
        if value:
          for entry in value.split(","):
            if not "=" in entry:
              if validate: raise ValueError(error_msg)
              else: continue
            
            locale, count = entry.split("=", 1)
            
            if re.match("^[a-zA-Z0-9\?]{2}$", locale) and count.isdigit():
              locale_usage[locale] = int(count)
            elif validate:
              raise ValueError(error_msg)
        if keyword == "dirreq-v2-ips":
          self.dir_v2_ips = locale_usage
        elif keyword == "dirreq-v3-ips":
          self.dir_v3_ips = locale_usage
        elif keyword == "dirreq-v2-reqs":
          self.dir_v2_requests = locale_usage
        elif keyword == "dirreq-v3-reqs":
          self.dir_v3_requests = locale_usage
        elif keyword == "geoip-client-origins":
          self.geoip_client_origins = locale_usage
        elif keyword == "entry-ips":
          self.entry_ips = locale_usage
        elif keyword == "bridge-ips":
          self.bridge_ips = locale_usage
      elif keyword == "router-signature":
        if validate and not block_contents:
          raise ValueError("Router signature line must be followed by a signature block: %s" % line)
        
        self.signature = block_contents
      else:
        self._unrecognized_lines.append(line)

