"""
Package for parsing and processing descriptor data.

**Module Overview:**

::

  parse_file - Parses the descriptors in a file.

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
  "router_status_entry",
  "parse_file",
  "Descriptor",
]

import os
import re

import stem.prereq
import stem.util.str_tools

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

KEYWORD_CHAR = "a-zA-Z0-9-"
WHITESPACE = " \t"
KEYWORD_LINE = re.compile("^([%s]+)(?:[%s]+(.*))?$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_START = re.compile("^-----BEGIN ([%s%s]+)-----$" % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END = "-----END %s-----"


def parse_file(descriptor_file, descriptor_type = None, path = None, validate = True):
  """
  Simple function to read the descriptor contents from a file, providing an
  iterator for its :class:`~stem.descriptor.__init__.Descriptor` contents.

  If you don't provide a **descriptor_type** argument then this automatically
  tries to determine the descriptor type based on the following...

  * The @type annotation on the first line. These are generally only found in
    the `descriptor archives <https://metrics.torproject.org>`_.

  * The filename if it matches something from tor's data directory. For
    instance, tor's 'cached-descriptors' contains server descriptors.

  This is a handy function for simple usage, but if you're reading multiple
  descriptor files you might want to consider the
  :class:`~stem.descriptor.reader.DescriptorReader`.

  Descriptor types include the following, including further minor versions (ie.
  if we support 1.0 then we also support 1.1 and above)...

  ========================================= =====
  Descriptor Type                           Class
  ========================================= =====
  server-descriptor 1.0                     :class:`~stem.descriptor.server_descriptor.RelayDescriptor`
  extra-info 1.0                            :class:`~stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`
  directory 1.0                             **unsupported**
  network-status-2 1.0                      :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV2` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV2`)
  dir-key-certificate-3 1.0                 :class:`~stem.descriptor.networkstatus.KeyCertificate`
  network-status-consensus-3 1.0            :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`)
  network-status-vote-3 1.0                 :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`)
  network-status-microdesc-consensus-3 1.0  :class:`~stem.descriptor.router_status_entry.RouterStatusEntryMicroV3` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`)
  bridge-network-status 1.0                 :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` (with a :class:`~stem.descriptor.networkstatus.BridgeNetworkStatusDocument`)
  bridge-server-descriptor 1.0              :class:`~stem.descriptor.server_descriptor.BridgeDescriptor`
  bridge-extra-info 1.0                     :class:`~stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`
  torperf 1.0                               **unsupported**
  bridge-pool-assignment 1.0                **unsupported**
  tordnsel 1.0                              **unsupported**
  ========================================= =====

  If you're using **python 3** then beware that the open() function defaults to
  using **text mode**. **Binary mode** is strongly suggested because it's both
  faster (by my testing by about 33x) and doesn't do universal newline
  translation which can make us misparse the document.

  ::

    my_descriptor_file = open(descriptor_path, 'rb')

  :param file descriptor_file: opened file with the descriptor contents
  :param str descriptor_type: `descriptor type <https://metrics.torproject.org/formats.html#descriptortypes>`_, this is guessed if not provided
  :param str path: absolute path to the file's location on disk
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise

  :returns: iterator for :class:`~stem.descriptor.__init__.Descriptor` instances in the file

  :raises:
    * **TypeError** if we can't match the contents of the file to a descriptor type
    * **IOError** if unable to read from the descriptor_file
  """

  import stem.descriptor.server_descriptor
  import stem.descriptor.extrainfo_descriptor
  import stem.descriptor.networkstatus

  # attempt to read content as unicode

  descriptor_file = _UnicodeReader(descriptor_file)

  # The tor descriptor specifications do not provide a reliable method for
  # identifying a descriptor file's type and version so we need to guess
  # based on its filename. Metrics descriptors, however, can be identified
  # by an annotation on their first line...
  # https://trac.torproject.org/5651

  initial_position = descriptor_file.tell()
  first_line = descriptor_file.readline().strip()
  metrics_header_match = re.match("^@type (\S+) (\d+).(\d+)$", first_line)

  if not metrics_header_match:
    descriptor_file.seek(initial_position)

  filename = '<undefined>' if path is None else os.path.basename(path)
  file_parser = None

  if descriptor_type is not None:
    descriptor_type_match = re.match("^(\S+) (\d+).(\d+)$", descriptor_type)

    if descriptor_type_match:
      desc_type, major_version, minor_version = descriptor_type_match.groups()
      file_parser = lambda f: _parse_metrics_file(desc_type, int(major_version), int(minor_version), f, validate)
    else:
      raise ValueError("The descriptor_type must be of the form '<type> <major_version>.<minor_version>'")
  elif metrics_header_match:
    # Metrics descriptor handling

    desc_type, major_version, minor_version = metrics_header_match.groups()
    file_parser = lambda f: _parse_metrics_file(desc_type, int(major_version), int(minor_version), f, validate)
  else:
    # Cached descriptor handling. These contain multiple descriptors per file.

    if filename == "cached-descriptors":
      file_parser = lambda f: stem.descriptor.server_descriptor._parse_file(f, validate = validate)
    elif filename == "cached-extrainfo":
      file_parser = lambda f: stem.descriptor.extrainfo_descriptor._parse_file(f, validate = validate)
    elif filename == "cached-consensus":
      file_parser = lambda f: stem.descriptor.networkstatus._parse_file(f, validate = validate)
    elif filename == "cached-microdesc-consensus":
      file_parser = lambda f: stem.descriptor.networkstatus._parse_file(f, is_microdescriptor = True, validate = validate)

  if file_parser:
    for desc in file_parser(descriptor_file):
      if path is not None:
        desc._set_path(path)

      yield desc

    return

  # Not recognized as a descriptor file.

  raise TypeError("Unable to determine the descriptor's type. filename: '%s', first line: '%s'" % (filename, first_line))


def _parse_metrics_file(descriptor_type, major_version, minor_version, descriptor_file, validate):
  # Parses descriptor files from metrics, yielding individual descriptors. This
  # throws a TypeError if the descriptor_type or version isn't recognized.
  import stem.descriptor.server_descriptor
  import stem.descriptor.extrainfo_descriptor
  import stem.descriptor.networkstatus

  if descriptor_type == "server-descriptor" and major_version == 1:
    for desc in stem.descriptor.server_descriptor._parse_file(descriptor_file, is_bridge = False, validate = validate):
      yield desc
  elif descriptor_type == "bridge-server-descriptor" and major_version == 1:
    for desc in stem.descriptor.server_descriptor._parse_file(descriptor_file, is_bridge = True, validate = validate):
      yield desc
  elif descriptor_type == "extra-info" and major_version == 1:
    for desc in stem.descriptor.extrainfo_descriptor._parse_file(descriptor_file, is_bridge = False, validate = validate):
      yield desc
  elif descriptor_type == "bridge-extra-info" and major_version == 1:
    # version 1.1 introduced a 'transport' field...
    # https://trac.torproject.org/6257

    for desc in stem.descriptor.extrainfo_descriptor._parse_file(descriptor_file, is_bridge = True, validate = validate):
      yield desc
  elif descriptor_type == "network-status-2" and major_version == 1:
    document_type = stem.descriptor.networkstatus.NetworkStatusDocumentV2

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, validate = validate):
      yield desc
  elif descriptor_type == "dir-key-certificate-3" and major_version == 1:
    yield stem.descriptor.networkstatus.KeyCertificate(descriptor_file.read(), validate = validate)
  elif descriptor_type in ("network-status-consensus-3", "network-status-vote-3") and major_version == 1:
    document_type = stem.descriptor.networkstatus.NetworkStatusDocumentV3

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, validate = validate):
      yield desc
  elif descriptor_type == "network-status-microdesc-consensus-3" and major_version == 1:
    document_type = stem.descriptor.networkstatus.NetworkStatusDocumentV3

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, is_microdescriptor = True, validate = validate):
      yield desc
  elif descriptor_type == "bridge-network-status" and major_version == 1:
    document_type = stem.descriptor.networkstatus.BridgeNetworkStatusDocument

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, validate = validate):
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

    :returns: **str** with the absolute path of the descriptor source
    """

    return self._path

  def get_unrecognized_lines(self):
    """
    Provides a list of lines that were either ignored or had data that we did
    not know how to process. This is most common due to new descriptor fields
    that this library does not yet know how to process. Patches welcome!

    :returns: **list** of lines of unrecognized content
    """

    raise NotImplementedError

  def _set_path(self, path):
    self._path = path

  def __str__(self):
    return self._raw_contents


class _UnicodeReader(object):
  """
  File-like object that wraps another file. This replaces read ASCII bytes with
  unicode content. This only supports read operations.
  """

  def __init__(self, wrapped_file):
    self.wrapped_file = wrapped_file

  def close(self):
    return self.wrapped_file.close()

  def getvalue(self):
    return self.wrapped_file.getvalue()

  def isatty(self):
    return self.wrapped_file.isatty()

  def next(self):
    return self.wrapped_file.next()

  def read(self, n = -1):
    return stem.util.str_tools.to_unicode(self.wrapped_file.read(n))

  def readline(self):
    return stem.util.str_tools.to_unicode(self.wrapped_file.readline())

  def readlines(self, sizehint = 0):
    # being careful to do in-place conversion so we don't accidently double our
    # memory usage

    results = self.wrapped_file.readlines(sizehint)

    for i in xrange(len(results)):
      results[i] = stem.util.str_tools.to_unicode(results[i])

    return results

  def seek(self, pos, mode = 0):
    return self.wrapped_file.seek(pos, mode)

  def tell(self):
    return self.wrapped_file.tell()


def _read_until_keywords(keywords, descriptor_file, inclusive = False, ignore_first = False, skip = False, end_position = None, include_ending_keyword = False):
  """
  Reads from the descriptor file until we get to one of the given keywords or reach the
  end of the file.

  :param str,list keywords: keyword(s) we want to read until
  :param file descriptor_file: file with the descriptor content
  :param bool inclusive: includes the line with the keyword if True
  :param bool ignore_first: doesn't check if the first line read has one of the
    given keywords
  :param bool skip: skips buffering content, returning None
  :param int end_position: end if we reach this point in the file
  :param bool include_ending_keyword: provides the keyword we broke on if **True**

  :returns: **list** with the lines until we find one of the keywords, this is a two value tuple with the ending keyword if include_ending_keyword is **True**
  """

  content = None if skip else []
  ending_keyword = None

  if isinstance(keywords, str):
    keywords = (keywords,)

  if ignore_first:
    first_line = descriptor_file.readline()

    if content is not None and first_line is not None:
      content.append(first_line)

  while True:
    last_position = descriptor_file.tell()

    if end_position and last_position >= end_position:
      break

    line = descriptor_file.readline()

    if not line:
      break  # EOF

    line_match = KEYWORD_LINE.match(line)

    if not line_match:
      # no spaces or tabs in the line
      line_keyword = line.strip()
    else:
      line_keyword = line_match.groups()[0]

    if line_keyword in keywords:
      ending_keyword = line_keyword

      if not inclusive:
        descriptor_file.seek(last_position)
      elif content is not None:
        content.append(line)

      break
    elif content is not None:
      content.append(line)

  if include_ending_keyword:
    return (content, ending_keyword)
  else:
    return content


def _get_pseudo_pgp_block(remaining_contents):
  """
  Checks if given contents begins with a pseudo-Open-PGP-style block and, if
  so, pops it off and provides it back to the caller.

  :param list remaining_contents: lines to be checked for a public key block

  :returns: **str** with the armor wrapped contents or None if it doesn't exist

  :raises: **ValueError** if the contents starts with a key block but it's
    malformed (for instance, if it lacks an ending line)
  """

  if not remaining_contents:
    return None  # nothing left

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

  To get a sub-listing with just certain keywords use extra_keywords. This can
  be useful if we care about their relative ordering with respect to each
  other. For instance, we care about the ordering of 'accept' and 'reject'
  entries because this influences the resulting exit policy, but for everything
  else in server descriptors the order does not matter.

  :param str raw_contents: descriptor content provided by the relay
  :param bool validate: checks the validity of the descriptor's content if
    True, skips these checks otherwise
  :param list extra_keywords: entity keywords to put into a separate listing
    with ordering intact

  :returns:
    **collections.OrderedDict** with the 'keyword => (value, pgp key) entries'
    mappings. If a extra_keywords was provided then this instead provides a two
    value tuple, the second being a list of those entries.
  """

  entries = OrderedDict()
  extra_entries = []  # entries with a keyword in extra_keywords
  remaining_lines = raw_contents.split("\n")

  while remaining_lines:
    line = remaining_lines.pop(0)

    # V2 network status documents explicitly can contain blank lines...
    #
    #   "Implementations MAY insert blank lines for clarity between sections;
    #   these blank lines are ignored."
    #
    # ... and server descriptors end with an extra newline. But other documents
    # don't say how blank lines should be handled so globally ignoring them.

    if not line:
      continue

    # Some lines have an 'opt ' for backward compatibility. They should be
    # ignored. This prefix is being removed in...
    # https://trac.torproject.org/projects/tor/ticket/5124

    if line.startswith("opt "):
      line = line[4:]

    line_match = KEYWORD_LINE.match(line)

    if not line_match:
      if not validate:
        continue

      raise ValueError("Line contains invalid characters: %s" % line)

    keyword, value = line_match.groups()

    if value is None:
      value = ''

    try:
      block_contents = _get_pseudo_pgp_block(remaining_lines)
    except ValueError, exc:
      if not validate:
        continue

      raise exc

    if keyword in extra_keywords:
      extra_entries.append("%s %s" % (keyword, value))
    else:
      entries.setdefault(keyword, []).append((value, block_contents))

  if extra_keywords:
    return entries, extra_entries
  else:
    return entries
