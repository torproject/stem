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
"""

import stem.descriptor

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

class ExtraInfoDescriptor(stem.descriptor.Descriptor):
  """
  Extra-info descriptor document.
  
  Attributes:
    nickname (str)           - relay's nickname (*)
    fingerprint (str)        - fourty hex digits that make up the relay's fingerprint (*)
    published (datetime.datetime) - time in GMT when the descriptor was generated (*)
    geoip_db_digest (str)    - sha1 of geoIP database file
    
    read_history (str)       - read-history line, always unset
    read_history_end (datetime.datetime) - end of the sampling interval
    read_history_interval (int) - seconds per interval
    read_history_values (list) - bytes read during each interval (*)
    
    write_history (str)      - write-history line, always unset
    write_history_end (datetime.datetime) - end of the sampling interval
    write_history_interval (int) - seconds per interval
    write_history_values (list) - bytes written during each interval (*)
    
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
    
    self.read_history = None
    self.read_history_end = None
    self.read_history_interval = None
    self.read_history_values = []
    
    self.write_history = None
    self.write_history_end = None
    self.write_history_interval = None
    self.write_history_values = []

