# Copyright 2012-2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Package for parsing and processing descriptor data.

**Module Overview:**

::

  parse_file - Parses the descriptors in a file.
  create - Creates a new custom descriptor.
  create_signing_key - Cretes a signing key that can be used for creating descriptors.

  Descriptor - Common parent for all descriptor file types.
    |- get_path - location of the descriptor on disk if it came from a file
    |- get_archive_path - location of the descriptor within the archive it came from
    |- get_bytes - similar to str(), but provides our original bytes content
    |- get_unrecognized_lines - unparsed descriptor content
    +- __str__ - string that the descriptor was made from

.. data:: DocumentHandler (enum)

  Ways in which we can parse a
  :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`.

  Both **ENTRIES** and **BARE_DOCUMENT** have a 'thin' document, which doesn't
  have a populated **routers** attribute. This allows for lower memory usage
  and upfront runtime. However, if read time and memory aren't a concern then
  **DOCUMENT** can provide you with a fully populated document.

  Handlers don't change the fact that most methods that provide
  descriptors return an iterator. In the case of **DOCUMENT** and
  **BARE_DOCUMENT** that iterator would have just a single item -
  the document itself.

  Simple way to handle this is to call **next()** to get the iterator's one and
  only value...

  ::

    import stem.descriptor.remote
    from stem.descriptor import DocumentHandler

    consensus = next(stem.descriptor.remote.get_consensus(
      document_handler = DocumentHandler.BARE_DOCUMENT,
    )


  =================== ===========
  DocumentHandler     Description
  =================== ===========
  **ENTRIES**         Iterates over the contained :class:`~stem.descriptor.router_status_entry.RouterStatusEntry`. Each has a reference to the bare document it came from (through its **document** attribute).
  **DOCUMENT**        :class:`~stem.descriptor.networkstatus.NetworkStatusDocument` with the :class:`~stem.descriptor.router_status_entry.RouterStatusEntry` it contains (through its **routers** attribute).
  **BARE_DOCUMENT**   :class:`~stem.descriptor.networkstatus.NetworkStatusDocument` **without** a reference to its contents (the :class:`~stem.descriptor.router_status_entry.RouterStatusEntry` are unread).
  =================== ===========
"""

import base64
import codecs
import collections
import copy
import hashlib
import os
import random
import re
import string
import tarfile

import stem.prereq
import stem.util
import stem.util.enum
import stem.util.str_tools
import stem.util.system

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

__all__ = [
  'export',
  'reader',
  'remote',
  'extrainfo_descriptor',
  'server_descriptor',
  'microdescriptor',
  'networkstatus',
  'router_status_entry',
  'tordnsel',
  'parse_file',
  'Descriptor',
]

UNSEEKABLE_MSG = """\
File object isn't seekable. Try wrapping it with a BytesIO instead...

  content = my_file.read()
  parsed_descriptors = stem.descriptor.parse_file(io.BytesIO(content))
"""

KEYWORD_CHAR = 'a-zA-Z0-9-'
WHITESPACE = ' \t'
KEYWORD_LINE = re.compile('^([%s]+)(?:[%s]+(.*))?$' % (KEYWORD_CHAR, WHITESPACE))
SPECIFIC_KEYWORD_LINE = '^(%%s)(?:[%s]+(.*))?$' % WHITESPACE
PGP_BLOCK_START = re.compile('^-----BEGIN ([%s%s]+)-----$' % (KEYWORD_CHAR, WHITESPACE))
PGP_BLOCK_END = '-----END %s-----'
EMPTY_COLLECTION = ([], {}, set())

DIGEST_TYPE_INFO = b'\x00\x01'
DIGEST_PADDING = b'\xFF'
DIGEST_SEPARATOR = b'\x00'

CRYPTO_BLOB = """
MIGJAoGBAJv5IIWQ+WDWYUdyA/0L8qbIkEVH/cwryZWoIaPAzINfrw1WfNZGtBmg
skFtXhOHHqTRN4GPPrZsAIUOQGzQtGb66IQgT4tO/pj+P6QmSCCdTfhvGfgTCsC+
WPi4Fl2qryzTb3QO5r5x7T8OsG2IBUET1bLQzmtbC560SYR49IvVAgMBAAE=
"""

DocumentHandler = stem.util.enum.UppercaseEnum(
  'ENTRIES',
  'DOCUMENT',
  'BARE_DOCUMENT',
)


class SigningKey(collections.namedtuple('SigningKey', ['private', 'public', 'public_digest'])):
  """
  Key used by relays to sign their server and extrainfo descriptors.

  .. versionadded:: 1.6.0

  :var cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey private: private key
  :var cryptography.hazmat.backends.openssl.rsa._RSAPublicKey public: public key
  :var bytes public_digest: block that can be used for the a server descrptor's 'signing-key' field
  """


def parse_file(descriptor_file, descriptor_type = None, validate = False, document_handler = DocumentHandler.ENTRIES, normalize_newlines = None, **kwargs):
  """
  Simple function to read the descriptor contents from a file, providing an
  iterator for its :class:`~stem.descriptor.__init__.Descriptor` contents.

  If you don't provide a **descriptor_type** argument then this automatically
  tries to determine the descriptor type based on the following...

  * The @type annotation on the first line. These are generally only found in
    the `CollecTor archives <https://metrics.torproject.org/collector.html#relay-descriptors>`_.

  * The filename if it matches something from tor's data directory. For
    instance, tor's 'cached-descriptors' contains server descriptors.

  This is a handy function for simple usage, but if you're reading multiple
  descriptor files you might want to consider the
  :class:`~stem.descriptor.reader.DescriptorReader`.

  Descriptor types include the following, including further minor versions (ie.
  if we support 1.1 then we also support everything from 1.0 and most things
  from 1.2, but not 2.0)...

  ========================================= =====
  Descriptor Type                           Class
  ========================================= =====
  server-descriptor 1.0                     :class:`~stem.descriptor.server_descriptor.RelayDescriptor`
  extra-info 1.0                            :class:`~stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor`
  microdescriptor 1.0                       :class:`~stem.descriptor.microdescriptor.Microdescriptor`
  directory 1.0                             **unsupported**
  network-status-2 1.0                      :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV2` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV2`)
  dir-key-certificate-3 1.0                 :class:`~stem.descriptor.networkstatus.KeyCertificate`
  network-status-consensus-3 1.0            :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`)
  network-status-vote-3 1.0                 :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`)
  network-status-microdesc-consensus-3 1.0  :class:`~stem.descriptor.router_status_entry.RouterStatusEntryMicroV3` (with a :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`)
  bridge-network-status 1.0                 :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` (with a :class:`~stem.descriptor.networkstatus.BridgeNetworkStatusDocument`)
  bridge-server-descriptor 1.0              :class:`~stem.descriptor.server_descriptor.BridgeDescriptor`
  bridge-extra-info 1.1 or 1.2              :class:`~stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor`
  torperf 1.0                               **unsupported**
  bridge-pool-assignment 1.0                **unsupported**
  tordnsel 1.0                              :class:`~stem.descriptor.tordnsel.TorDNSEL`
  hidden-service-descriptor 1.0             :class:`~stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor`
  ========================================= =====

  If you're using **python 3** then beware that the open() function defaults to
  using text mode. **Binary mode** is strongly suggested because it's both
  faster (by my testing by about 33x) and doesn't do universal newline
  translation which can make us misparse the document.

  ::

    my_descriptor_file = open(descriptor_path, 'rb')

  :param str,file,tarfile descriptor_file: path or opened file with the descriptor contents
  :param str descriptor_type: `descriptor type <https://metrics.torproject.org/collector.html#data-formats>`_, this is guessed if not provided
  :param bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse the :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :param bool normalize_newlines: converts windows newlines (CRLF), this is the
    default when reading data directories on windows
  :param dict kwargs: additional arguments for the descriptor constructor

  :returns: iterator for :class:`~stem.descriptor.__init__.Descriptor` instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is True
    * **TypeError** if we can't match the contents of the file to a descriptor type
    * **IOError** if unable to read from the descriptor_file
  """

  # Delegate to a helper if this is a path or tarfile.

  handler = None

  if stem.util._is_str(descriptor_file):
    if stem.util.system.is_tarfile(descriptor_file):
      handler = _parse_file_for_tar_path
    else:
      handler = _parse_file_for_path
  elif isinstance(descriptor_file, tarfile.TarFile):
    handler = _parse_file_for_tarfile

  if handler:
    for desc in handler(descriptor_file, descriptor_type, validate, document_handler, **kwargs):
      yield desc

    return

  # Not all files are seekable. If unseekable then advising the user.
  #
  # Python 3.x adds an io.seekable() method, but not an option with python 2.x
  # so using an experimental call to tell() to determine this.

  try:
    descriptor_file.tell()
  except IOError:
    raise IOError(UNSEEKABLE_MSG)

  # The tor descriptor specifications do not provide a reliable method for
  # identifying a descriptor file's type and version so we need to guess
  # based on its filename. Metrics descriptors, however, can be identified
  # by an annotation on their first line...
  # https://trac.torproject.org/5651

  initial_position = descriptor_file.tell()
  first_line = stem.util.str_tools._to_unicode(descriptor_file.readline().strip())
  metrics_header_match = re.match('^@type (\S+) (\d+).(\d+)$', first_line)

  if not metrics_header_match:
    descriptor_file.seek(initial_position)

  descriptor_path = getattr(descriptor_file, 'name', None)
  filename = '<undefined>' if descriptor_path is None else os.path.basename(descriptor_file.name)

  def parse(descriptor_file):
    if normalize_newlines:
      descriptor_file = NewlineNormalizer(descriptor_file)

    if descriptor_type is not None:
      descriptor_type_match = re.match('^(\S+) (\d+).(\d+)$', descriptor_type)

      if descriptor_type_match:
        desc_type, major_version, minor_version = descriptor_type_match.groups()
        return _parse_metrics_file(desc_type, int(major_version), int(minor_version), descriptor_file, validate, document_handler, **kwargs)
      else:
        raise ValueError("The descriptor_type must be of the form '<type> <major_version>.<minor_version>'")
    elif metrics_header_match:
      # Metrics descriptor handling

      desc_type, major_version, minor_version = metrics_header_match.groups()
      return _parse_metrics_file(desc_type, int(major_version), int(minor_version), descriptor_file, validate, document_handler, **kwargs)
    else:
      # Cached descriptor handling. These contain multiple descriptors per file.

      if normalize_newlines is None and stem.util.system.is_windows():
        descriptor_file = NewlineNormalizer(descriptor_file)

      if filename == 'cached-descriptors' or filename == 'cached-descriptors.new':
        return stem.descriptor.server_descriptor._parse_file(descriptor_file, validate = validate, **kwargs)
      elif filename == 'cached-extrainfo' or filename == 'cached-extrainfo.new':
        return stem.descriptor.extrainfo_descriptor._parse_file(descriptor_file, validate = validate, **kwargs)
      elif filename == 'cached-microdescs' or filename == 'cached-microdescs.new':
        return stem.descriptor.microdescriptor._parse_file(descriptor_file, validate = validate, **kwargs)
      elif filename == 'cached-consensus':
        return stem.descriptor.networkstatus._parse_file(descriptor_file, validate = validate, document_handler = document_handler, **kwargs)
      elif filename == 'cached-microdesc-consensus':
        return stem.descriptor.networkstatus._parse_file(descriptor_file, is_microdescriptor = True, validate = validate, document_handler = document_handler, **kwargs)
      else:
        raise TypeError("Unable to determine the descriptor's type. filename: '%s', first line: '%s'" % (filename, first_line))

  for desc in parse(descriptor_file):
    if descriptor_path is not None:
      desc._set_path(os.path.abspath(descriptor_path))

    yield desc


def _parse_file_for_path(descriptor_file, *args, **kwargs):
  with open(descriptor_file, 'rb') as desc_file:
    for desc in parse_file(desc_file, *args, **kwargs):
      yield desc


def _parse_file_for_tar_path(descriptor_file, *args, **kwargs):
  # TODO: use 'with' for tarfile after dropping python 2.6 support
  tar_file = tarfile.open(descriptor_file)

  try:
    for desc in parse_file(tar_file, *args, **kwargs):
      desc._set_path(os.path.abspath(descriptor_file))
      yield desc
  finally:
    if tar_file:
      tar_file.close()


def _parse_file_for_tarfile(descriptor_file, *args, **kwargs):
  for tar_entry in descriptor_file:
    if tar_entry.isfile():
      entry = descriptor_file.extractfile(tar_entry)

      if tar_entry.size == 0:
        continue

      try:
        for desc in parse_file(entry, *args, **kwargs):
          desc._set_archive_path(entry.name)
          yield desc
      finally:
        entry.close()


def _parse_metrics_file(descriptor_type, major_version, minor_version, descriptor_file, validate, document_handler, **kwargs):
  # Parses descriptor files from metrics, yielding individual descriptors. This
  # throws a TypeError if the descriptor_type or version isn't recognized.

  if descriptor_type == 'server-descriptor' and major_version == 1:
    for desc in stem.descriptor.server_descriptor._parse_file(descriptor_file, is_bridge = False, validate = validate, **kwargs):
      yield desc
  elif descriptor_type == 'bridge-server-descriptor' and major_version == 1:
    for desc in stem.descriptor.server_descriptor._parse_file(descriptor_file, is_bridge = True, validate = validate, **kwargs):
      yield desc
  elif descriptor_type == 'extra-info' and major_version == 1:
    for desc in stem.descriptor.extrainfo_descriptor._parse_file(descriptor_file, is_bridge = False, validate = validate, **kwargs):
      yield desc
  elif descriptor_type == 'microdescriptor' and major_version == 1:
    for desc in stem.descriptor.microdescriptor._parse_file(descriptor_file, validate = validate, **kwargs):
      yield desc
  elif descriptor_type == 'bridge-extra-info' and major_version == 1:
    # version 1.1 introduced a 'transport' field...
    # https://trac.torproject.org/6257

    for desc in stem.descriptor.extrainfo_descriptor._parse_file(descriptor_file, is_bridge = True, validate = validate, **kwargs):
      yield desc
  elif descriptor_type == 'network-status-2' and major_version == 1:
    document_type = stem.descriptor.networkstatus.NetworkStatusDocumentV2

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, validate = validate, document_handler = document_handler, **kwargs):
      yield desc
  elif descriptor_type == 'dir-key-certificate-3' and major_version == 1:
    for desc in stem.descriptor.networkstatus._parse_file_key_certs(descriptor_file, validate = validate, **kwargs):
      yield desc
  elif descriptor_type in ('network-status-consensus-3', 'network-status-vote-3') and major_version == 1:
    document_type = stem.descriptor.networkstatus.NetworkStatusDocumentV3

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, validate = validate, document_handler = document_handler, **kwargs):
      yield desc
  elif descriptor_type == 'network-status-microdesc-consensus-3' and major_version == 1:
    document_type = stem.descriptor.networkstatus.NetworkStatusDocumentV3

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, is_microdescriptor = True, validate = validate, document_handler = document_handler, **kwargs):
      yield desc
  elif descriptor_type == 'bridge-network-status' and major_version == 1:
    document_type = stem.descriptor.networkstatus.BridgeNetworkStatusDocument

    for desc in stem.descriptor.networkstatus._parse_file(descriptor_file, document_type, validate = validate, document_handler = document_handler, **kwargs):
      yield desc
  elif descriptor_type == 'tordnsel' and major_version == 1:
    document_type = stem.descriptor.tordnsel.TorDNSEL

    for desc in stem.descriptor.tordnsel._parse_file(descriptor_file, validate = validate, **kwargs):
      yield desc
  elif descriptor_type == 'hidden-service-descriptor' and major_version == 1:
    document_type = stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor

    for desc in stem.descriptor.hidden_service_descriptor._parse_file(descriptor_file, validate = validate, **kwargs):
      yield desc
  else:
    raise TypeError("Unrecognized metrics descriptor format. type: '%s', version: '%i.%i'" % (descriptor_type, major_version, minor_version))


def _descriptor_content(attr = None, exclude = (), header_template = (), footer_template = ()):
  """
  Constructs a minimal descriptor with the given attributes. The content we
  provide back is of the form...

  * header_template (with matching attr filled in)
  * unused attr entries
  * footer_template (with matching attr filled in)

  So for instance...

  ::

    _descriptor_content(
      attr = {'nickname': 'caerSidi', 'contact': 'atagar'},
      header_template = (
        ('nickname', 'foobar'),
        ('fingerprint', '12345'),
      ),
    )

  ... would result in...

  ::

    nickname caerSidi
    fingerprint 12345
    contact atagar

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param tuple header_template: key/value pairs for mandatory fields before unrecognized content
  :param tuple footer_template: key/value pairs for mandatory fields after unrecognized content

  :returns: bytes with the requested descriptor content
  """

  header_content, footer_content = [], []
  attr = {} if attr is None else OrderedDict(attr)  # shallow copy since we're destructive

  for content, template in ((header_content, header_template),
                            (footer_content, footer_template)):
    for keyword, value in template:
      if keyword in exclude:
        continue

      value = stem.util.str_tools._to_unicode(attr.pop(keyword, value))

      if value is None:
        continue
      elif isinstance(value, (tuple, list)):
        for v in value:
          content.append('%s %s' % (keyword, v))
      elif value == '':
        content.append(keyword)
      elif value.startswith('\n'):
        # some values like crypto follow the line instead
        content.append('%s%s' % (keyword, value))
      else:
        content.append('%s %s' % (keyword, value))

  remainder = []

  for k, v in attr.items():
    if isinstance(v, (tuple, list)):
      remainder += ['%s %s' % (k, entry) for entry in v]
    else:
      remainder.append('%s %s' % (k, v))

  return stem.util.str_tools._to_bytes('\n'.join(header_content + remainder + footer_content))


def _value(line, entries):
  return entries[line][0][0]


def _values(line, entries):
  return [entry[0] for entry in entries[line]]


def _parse_simple_line(keyword, attribute, func = None):
  def _parse(descriptor, entries):
    value = _value(keyword, entries)
    setattr(descriptor, attribute, func(value) if func else value)

  return _parse


def _parse_if_present(keyword, attribute):
  return lambda descriptor, entries: setattr(descriptor, attribute, keyword in entries)


def _parse_bytes_line(keyword, attribute):
  def _parse(descriptor, entries):
    line_match = re.search(stem.util.str_tools._to_bytes('^(opt )?%s(?:[%s]+(.*))?$' % (keyword, WHITESPACE)), descriptor.get_bytes(), re.MULTILINE)
    result = None

    if line_match:
      value = line_match.groups()[1]
      result = b'' if value is None else value

    setattr(descriptor, attribute, result)

  return _parse


def _parse_timestamp_line(keyword, attribute):
  # "<keyword>" YYYY-MM-DD HH:MM:SS

  def _parse(descriptor, entries):
    value = _value(keyword, entries)

    try:
      setattr(descriptor, attribute, stem.util.str_tools._parse_timestamp(value))
    except ValueError:
      raise ValueError("Timestamp on %s line wasn't parsable: %s %s" % (keyword, keyword, value))

  return _parse


def _parse_forty_character_hex(keyword, attribute):
  # format of fingerprints, sha1 digests, etc

  def _parse(descriptor, entries):
    value = _value(keyword, entries)

    if not stem.util.tor_tools.is_hex_digits(value, 40):
      raise ValueError('%s line had an invalid value (should be 40 hex characters): %s %s' % (keyword, keyword, value))

    setattr(descriptor, attribute, value)

  return _parse


def _parse_protocol_line(keyword, attribute):
  def _parse(descriptor, entries):
    # parses 'protocol' entries like: Cons=1-2 Desc=1-2 DirCache=1 HSDir=1

    value = _value(keyword, entries)
    protocols = OrderedDict()

    for k, v in _mappings_for(keyword, value):
      versions = []

      if not v:
        continue

      for entry in v.split(','):
        if '-' in entry:
          min_value, max_value = entry.split('-', 1)
        else:
          min_value = max_value = entry

        if not min_value.isdigit() or not max_value.isdigit():
          raise ValueError('Protocol values should be a number or number range, but was: %s %s' % (keyword, value))

        versions += range(int(min_value), int(max_value) + 1)

      protocols[k] = versions

    setattr(descriptor, attribute, protocols)

  return _parse


def _parse_key_block(keyword, attribute, expected_block_type, value_attribute = None):
  def _parse(descriptor, entries):
    value, block_type, block_contents = entries[keyword][0]

    if not block_contents or block_type != expected_block_type:
      raise ValueError("'%s' should be followed by a %s block, but was a %s" % (keyword, expected_block_type, block_type))

    setattr(descriptor, attribute, block_contents)

    if value_attribute:
      setattr(descriptor, value_attribute, value)

  return _parse


def _mappings_for(keyword, value, require_value = False, divider = ' '):
  """
  Parses an attribute as a series of 'key=value' mappings. Unlike _parse_*
  functions this is a helper, returning the attribute value rather than setting
  a descriptor field. This way parsers can perform additional validations.

  :param str keyword: descriptor field being parsed
  :param str value: 'attribute => values' mappings to parse
  :param str divider: separator between the key/value mappings
  :param bool require_value: validates that values are not empty

  :returns: **generator** with the key/value of the map attribute

  :raises: **ValueError** if descriptor content is invalid
  """

  if value is None:
    return  # no descripoter value to process
  elif value == '':
    return  # descriptor field was present, but blank

  for entry in value.split(divider):
    if '=' not in entry:
      raise ValueError("'%s' should be a series of 'key=value' pairs but was: %s" % (keyword, value))

    k, v = entry.split('=', 1)

    if require_value and not v:
      raise ValueError("'%s' line's %s mapping had a blank value: %s" % (keyword, k, value))

    yield k, v


def _copy(default):
  if default is None or isinstance(default, (bool, stem.exit_policy.ExitPolicy)):
    return default  # immutable
  elif default in EMPTY_COLLECTION:
    return type(default)()  # collection construction tad faster than copy
  else:
    return copy.copy(default)


class Descriptor(object):
  """
  Common parent for all types of descriptors.
  """

  ATTRIBUTES = {}  # mapping of 'attribute' => (default_value, parsing_function)
  PARSER_FOR_LINE = {}  # line keyword to its associated parsing function

  def __init__(self, contents, lazy_load = False):
    self._path = None
    self._archive_path = None
    self._raw_contents = contents
    self._lazy_loading = lazy_load
    self._entries = {}
    self._unrecognized_lines = []

  @classmethod
  def content(cls, attr = None, exclude = (), sign = False):
    """
    Creates descriptor content with the given attributes. Mandatory fields are
    filled with dummy information unless data is supplied. This doesn't yet
    create a valid signature.

    .. versionadded:: 1.6.0

    :param dict attr: keyword/value mappings to be included in the descriptor
    :param list exclude: mandatory keywords to exclude from the descriptor, this
      results in an invalid descriptor
    :param bool sign: includes cryptographic signatures and digests if True

    :returns: **str** with the content of a descriptor

    :raises:
      * **ImportError** if cryptography is unavailable and sign is True
      * **NotImplementedError** if not implemented for this descriptor type
    """

    raise NotImplementedError("The create and content methods haven't been implemented for %s" % cls.__name__)

  @classmethod
  def create(cls, attr = None, exclude = (), validate = True, sign = False):
    """
    Creates a descriptor with the given attributes. Mandatory fields are filled
    with dummy information unless data is supplied. This doesn't yet create a
    valid signature.

    .. versionadded:: 1.6.0

    :param dict attr: keyword/value mappings to be included in the descriptor
    :param list exclude: mandatory keywords to exclude from the descriptor, this
      results in an invalid descriptor
    :param bool validate: checks the validity of the descriptor's content if
      **True**, skips these checks otherwise
    :param bool sign: includes cryptographic signatures and digests if True

    :returns: :class:`~stem.descriptor.Descriptor` subclass

    :raises:
      * **ValueError** if the contents is malformed and validate is True
      * **ImportError** if cryptography is unavailable and sign is True
      * **NotImplementedError** if not implemented for this descriptor type
    """

    return cls(cls.content(attr, exclude, sign), validate = validate)

  def get_path(self):
    """
    Provides the absolute path that we loaded this descriptor from.

    :returns: **str** with the absolute path of the descriptor source
    """

    return self._path

  def get_archive_path(self):
    """
    If this descriptor came from an archive then provides its path within the
    archive. This is only set if the descriptor came from a
    :class:`~stem.descriptor.reader.DescriptorReader`, and is **None** if this
    descriptor didn't come from an archive.

    :returns: **str** with the descriptor's path within the archive
    """

    return self._archive_path

  def get_bytes(self):
    """
    Provides the ASCII **bytes** of the descriptor. This only differs from
    **str()** if you're running python 3.x, in which case **str()** provides a
    **unicode** string.

    :returns: **bytes** for the descriptor's contents
    """

    return self._raw_contents

  def get_unrecognized_lines(self):
    """
    Provides a list of lines that were either ignored or had data that we did
    not know how to process. This is most common due to new descriptor fields
    that this library does not yet know how to process. Patches welcome!

    :returns: **list** of lines of unrecognized content
    """

    if self._lazy_loading:
      # we need to go ahead and parse the whole document to figure this out
      self._parse(self._entries, False)
      self._lazy_loading = False

    return list(self._unrecognized_lines)

  def _parse(self, entries, validate, parser_for_line = None):
    """
    Parses a series of 'keyword => (value, pgp block)' mappings and applies
    them as attributes.

    :param dict entries: descriptor contents to be applied
    :param bool validate: checks the validity of descriptor content if True
    :param dict parsers: mapping of lines to the function for parsing it

    :raises: **ValueError** if an error occurs in validation
    """

    if parser_for_line is None:
      parser_for_line = self.PARSER_FOR_LINE

    for keyword, values in list(entries.items()):
      try:
        if keyword in parser_for_line:
          parser_for_line[keyword](self, entries)
        else:
          for value, block_type, block_contents in values:
            line = '%s %s' % (keyword, value)

            if block_contents:
              line += '\n%s' % block_contents

            self._unrecognized_lines.append(line)
      except ValueError:
        if validate:
          raise

  def _set_path(self, path):
    self._path = path

  def _set_archive_path(self, path):
    self._archive_path = path

  def _name(self, is_plural = False):
    return str(type(self))

  def _digest_for_signature(self, signing_key, signature):
    """
    Provides the signed digest we should have given this key and signature.

    :param str signing_key: key block used to make this signature
    :param str signature: signed digest for this descriptor content

    :returns: the digest string encoded in uppercase hex

    :raises: ValueError if unable to provide a validly signed digest
    """

    if not stem.prereq.is_crypto_available():
      raise ValueError('Generating the signed digest requires the cryptography module')

    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_der_public_key
    from cryptography.utils import int_to_bytes, int_from_bytes

    key = load_der_public_key(_bytes_for_block(signing_key), default_backend())
    modulus = key.public_numbers().n
    public_exponent = key.public_numbers().e

    sig_as_bytes = _bytes_for_block(signature)
    sig_as_long = int_from_bytes(sig_as_bytes, byteorder='big')  # convert signature to an int
    blocksize = len(sig_as_bytes)  # 256B for NetworkStatusDocuments, 128B for others

    # use the public exponent[e] & the modulus[n] to decrypt the int
    decrypted_int = pow(sig_as_long, public_exponent, modulus)

    # convert the int to a byte array
    decrypted_bytes = int_to_bytes(decrypted_int, blocksize)

    ############################################################################
    # The decrypted bytes should have a structure exactly along these lines.
    # 1 byte  - [null '\x00']
    # 1 byte  - [block type identifier '\x01'] - Should always be 1
    # N bytes - [padding '\xFF' ]
    # 1 byte  - [separator '\x00' ]
    # M bytes - [message]
    # Total   - 128 bytes
    # More info here http://www.ietf.org/rfc/rfc2313.txt
    #                esp the Notes in section 8.1
    ############################################################################

    try:
      if decrypted_bytes.index(DIGEST_TYPE_INFO) != 0:
        raise ValueError('Verification failed, identifier missing')
    except ValueError:
      raise ValueError('Verification failed, malformed data')

    try:
      identifier_offset = 2

      # find the separator
      seperator_index = decrypted_bytes.index(DIGEST_SEPARATOR, identifier_offset)
    except ValueError:
      raise ValueError('Verification failed, seperator not found')

    digest_hex = codecs.encode(decrypted_bytes[seperator_index + 1:], 'hex_codec')
    return stem.util.str_tools._to_unicode(digest_hex.upper())

  def _digest_for_content(self, start, end):
    """
    Provides the digest of our descriptor's content in a given range.

    :param bytes start: start of the range to generate a digest for
    :param bytes end: end of the range to generate a digest for

    :returns: the digest string encoded in uppercase hex

    :raises: ValueError if the digest canot be calculated
    """

    raw_descriptor = self.get_bytes()

    start_index = raw_descriptor.find(start)
    end_index = raw_descriptor.find(end, start_index)

    if start_index == -1:
      raise ValueError("Digest is for the range starting with '%s' but that isn't in our descriptor" % start)
    elif end_index == -1:
      raise ValueError("Digest is for the range ending with '%s' but that isn't in our descriptor" % end)

    digest_content = raw_descriptor[start_index:end_index + len(end)]
    digest_hash = hashlib.sha1(stem.util.str_tools._to_bytes(digest_content))
    return stem.util.str_tools._to_unicode(digest_hash.hexdigest().upper())

  def __getattr__(self, name):
    # We can't use standard hasattr() since it calls this function, recursing.
    # Doing so works since it stops recursing after several dozen iterations
    # (not sure why), but horrible in terms of performance.

    def has_attr(attr):
      try:
        super(Descriptor, self).__getattribute__(attr)
        return True
      except:
        return False

    # If an attribute we should have isn't present it means either...
    #
    #   a. we still need to lazy load this
    #   b. we read the whole descriptor but it wasn't present, so needs the default

    if name in self.ATTRIBUTES and not has_attr(name):
      default, parsing_function = self.ATTRIBUTES[name]

      if self._lazy_loading:
        try:
          parsing_function(self, self._entries)
        except (ValueError, KeyError):
          # Set defaults for anything the parsing function should've covered.
          # Despite having a validation failure some attributes might be set in
          # which case we keep them.

          for attr_name, (attr_default, attr_parser) in self.ATTRIBUTES.items():
            if parsing_function == attr_parser and not has_attr(attr_name):
              setattr(self, attr_name, _copy(attr_default))
      else:
        setattr(self, name, _copy(default))

    return super(Descriptor, self).__getattribute__(name)

  def __str__(self):
    if stem.prereq.is_python_3():
      return stem.util.str_tools._to_unicode(self._raw_contents)
    else:
      return self._raw_contents


class NewlineNormalizer(object):
  """
  File wrapper that normalizes CRLF line endings.
  """

  def __init__(self, wrapped_file):
    self._wrapped_file = wrapped_file
    self.name = getattr(wrapped_file, 'name', None)

  def read(self, *args):
    return self._wrapped_file.read(*args).replace(b'\r\n', b'\n')

  def readline(self, *args):
    return self._wrapped_file.readline(*args).replace(b'\r\n', b'\n')

  def readlines(self, *args):
    return [line.rstrip(b'\r') for line in self._wrapped_file.readlines(*args)]

  def seek(self, *args):
    return self._wrapped_file.seek(*args)

  def tell(self, *args):
    return self._wrapped_file.tell(*args)


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

  :returns: **list** with the lines until we find one of the keywords, this is
    a two value tuple with the ending keyword if include_ending_keyword is
    **True**
  """

  content = None if skip else []
  ending_keyword = None

  if stem.util._is_str(keywords):
    keywords = (keywords,)

  if ignore_first:
    first_line = descriptor_file.readline()

    if first_line and content is not None:
      content.append(first_line)

  keyword_match = re.compile(SPECIFIC_KEYWORD_LINE % '|'.join(keywords))

  while True:
    last_position = descriptor_file.tell()

    if end_position and last_position >= end_position:
      break

    line = descriptor_file.readline()

    if not line:
      break  # EOF

    line_match = keyword_match.match(stem.util.str_tools._to_unicode(line))

    if line_match:
      ending_keyword = line_match.groups()[0]

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


def _bytes_for_block(content):
  """
  Provides the base64 decoded content of a pgp-style block.

  :param str content: block to be decoded

  :returns: decoded block content

  :raises: **TypeError** if this isn't base64 encoded content
  """

  # strip the '-----BEGIN RSA PUBLIC KEY-----' header and footer

  content = ''.join(content.split('\n')[1:-1])

  return base64.b64decode(stem.util.str_tools._to_bytes(content))


def _get_pseudo_pgp_block(remaining_contents):
  """
  Checks if given contents begins with a pseudo-Open-PGP-style block and, if
  so, pops it off and provides it back to the caller.

  :param list remaining_contents: lines to be checked for a public key block

  :returns: **tuple** of the (block_type, content) or None if it doesn't exist

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
        raise ValueError("Unterminated pgp style block (looking for '%s'):\n%s" % (end_line, '\n'.join(block_lines)))

      line = remaining_contents.pop(0)
      block_lines.append(line)

      if line == end_line:
        return (block_type, '\n'.join(block_lines))
  else:
    return None


def create_signing_key(private_key = None):
  """
  Serializes a signing key if we have one. Otherwise this creates a new signing
  key we can use to create descriptors.

  .. versionadded:: 1.6.0

  :param cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey private_key: private key

  :returns: :class:`~stem.descriptor.__init__.SigningKey` that can be used to
    create descriptors

  :raises: **ImportError** if the cryptography module is unavailable
  """

  if not stem.prereq.is_crypto_available():
    raise ImportError('Signing requires the cryptography module')

  from cryptography.hazmat.backends import default_backend
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.primitives.asymmetric import rsa

  if private_key is None:
    private_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 1024,
      backend = default_backend(),
    )

    # When signing the cryptography module includes a constant indicating
    # the hash algorithm used. Tor doesn't. This causes signature
    # validation failures and unfortunately cryptography have no nice way
    # of excluding these so we need to mock out part of their internals...
    #
    #   https://github.com/pyca/cryptography/issues/3713

    def no_op(*args, **kwargs):
      return 1

    private_key._backend._lib.EVP_PKEY_CTX_set_signature_md = no_op
    private_key._backend.openssl_assert = no_op

  public_key = private_key.public_key()
  public_digest = b'\n' + public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PublicFormat.PKCS1,
  ).strip()

  return SigningKey(private_key, public_key, public_digest)


def _append_router_signature(content, private_key):
  """
  Appends a router signature to a server or extrainfo descriptor.

  :param bytes content: descriptor content up through 'router-signature\\n'
  :param cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey private_key:
    private relay signing key

  :returns: **bytes** with the signed descriptor content
  """

  if not stem.prereq.is_crypto_available():
    raise ImportError('Signing requires the cryptography module')

  from cryptography.hazmat.primitives import hashes
  from cryptography.hazmat.primitives.asymmetric import padding

  signature = base64.b64encode(private_key.sign(content, padding.PKCS1v15(), hashes.SHA1()))
  return content + b'\n'.join([b'-----BEGIN SIGNATURE-----'] + stem.util.str_tools._split_by_length(signature, 64) + [b'-----END SIGNATURE-----\n'])


def _random_nickname():
  return ('Unnamed%i' % random.randint(0, 100000000000000))[:19]


def _random_fingerprint():
  return ('%040x' % random.randrange(16 ** 40)).upper()


def _random_ipv4_address():
  return '%i.%i.%i.%i' % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))


def _random_date():
  return '%i-%02i-%02i %02i:%02i:%02i' % (random.randint(2000, 2015), random.randint(1, 12), random.randint(1, 20), random.randint(0, 23), random.randint(0, 59), random.randint(0, 59))


def _random_crypto_blob(block_type = None):
  """
  Provides a random string that can be used for crypto blocks.
  """

  random_base64 = stem.util.str_tools._to_unicode(base64.b64encode(os.urandom(140)))
  crypto_blob = '\n'.join(stem.util.str_tools._split_by_length(random_base64, 64))

  if block_type:
    return '\n-----BEGIN %s-----\n%s\n-----END %s-----' % (block_type, crypto_blob, block_type)
  else:
    return crypto_blob


def _descriptor_components(raw_contents, validate, extra_keywords = (), non_ascii_fields = ()):
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
  :param list non_ascii_fields: fields containing non-ascii content

  :returns:
    **collections.OrderedDict** with the 'keyword => (value, pgp key) entries'
    mappings. If a extra_keywords was provided then this instead provides a two
    value tuple, the second being a list of those entries.
  """

  if isinstance(raw_contents, bytes):
    raw_contents = stem.util.str_tools._to_unicode(raw_contents)

  entries = OrderedDict()
  extra_entries = []  # entries with a keyword in extra_keywords
  remaining_lines = raw_contents.split('\n')

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

    if line.startswith('opt '):
      line = line[4:]

    line_match = KEYWORD_LINE.match(line)

    if not line_match:
      if not validate:
        continue

      raise ValueError('Line contains invalid characters: %s' % line)

    keyword, value = line_match.groups()

    if value is None:
      value = ''

    try:
      block_attr = _get_pseudo_pgp_block(remaining_lines)

      if block_attr:
        block_type, block_contents = block_attr
      else:
        block_type, block_contents = None, None
    except ValueError:
      if not validate:
        continue

      raise

    if validate and keyword not in non_ascii_fields:
      try:
        value.encode('ascii')
      except UnicodeError:
        replaced = ''.join([(char if char in string.printable else '?') for char in value])
        raise ValueError("'%s' line had non-ascii content: %s" % (keyword, replaced))

    if keyword in extra_keywords:
      extra_entries.append('%s %s' % (keyword, value))
    else:
      entries.setdefault(keyword, []).append((value, block_type, block_contents))

  if extra_keywords:
    return entries, extra_entries
  else:
    return entries


# importing at the end to avoid circular dependencies on our Descriptor class

import stem.descriptor.server_descriptor
import stem.descriptor.extrainfo_descriptor
import stem.descriptor.networkstatus
import stem.descriptor.microdescriptor
import stem.descriptor.tordnsel
import stem.descriptor.hidden_service_descriptor
