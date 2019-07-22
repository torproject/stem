# Copyright 2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for downloading from Tor's descriptor archive, CollecTor...

  https://collector.torproject.org/

This stores descriptors going back in time. If you need to know what the
network topology looked like at a past point in time, this is the place to go.

With this you can either download and read directly from CollecTor...

::

  import datetime
  import stem.descriptor.collector

  yesterday = datetime.date.today() - datetime.timedelta(1)

  # provide yesterday's exits

  for desc in stem.descriptor.collector.get_server_descriptors(start = yesterday):
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))

... or download the descriptors to disk and read them later.

::

  import datetime
  import os
  import stem.descriptor
  import stem.descriptor.collector

  yesterday = datetime.date.today() - datetime.timedelta(1)
  path = os.path.expanduser('~/descriptor_cache/server_desc_today')

  with open(path, 'wb') as cache_file:
    for desc in stem.descriptor.collector.get_server_descriptors(start = yesterday):
      cache_file.write(desc.get_bytes())

  # then later...

  for desc in stem.descriptor.parse_file(path, descriptor_type = 'server-descriptor 1.0'):
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))

.. versionadded:: 1.8.0
"""

import datetime
import json
import re
import sys
import time

from stem.descriptor import Compression
from stem.util import log

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

import stem.prereq
import stem.util.enum
import stem.util.str_tools

COLLECTOR_URL = 'https://collector.torproject.org/'
REFRESH_INDEX_RATE = 3600  # get new index if cached copy is an hour old

YEAR_DATE = re.compile('-(\\d{4})-(\\d{2})\\.')
SEC_DATE = re.compile('(\\d{4}-\\d{2}-\\d{2}-\\d{2}-\\d{2}-\\d{2})')

# distant future date so we can sort files without a timestamp at the end

FUTURE = datetime.datetime(9999, 1, 1)

# mapping of path prefixes to their descriptor type (sampled 7/11/19)

COLLECTOR_DESC_TYPES = {
  'archive/bridge-descriptors/server-descriptors/': 'bridge-server-descriptor 1.2',
  'archive/bridge-descriptors/extra-infos/': 'bridge-extra-info 1.3',
  'archive/bridge-descriptors/statuses/': 'bridge-network-status 1.1',
  'archive/bridge-pool-assignments/': 'bridge-pool-assignment 1.0',
  'archive/exit-lists/': 'tordnsel 1.0',
  'archive/relay-descriptors/bandwidths/': 'bandwidth-file 1.0',
  'archive/relay-descriptors/certs': 'dir-key-certificate-3 1.0',
  'archive/relay-descriptors/consensuses/': 'network-status-consensus-3 1.0',
  'archive/relay-descriptors/extra-infos/': 'extra-info 1.0',
  'archive/relay-descriptors/microdescs/': ('network-status-microdesc-consensus-3 1.0', 'microdescriptor 1.0'),
  'archive/relay-descriptors/server-descriptors/': 'server-descriptor 1.0',
  'archive/relay-descriptors/statuses/': 'network-status-2 1.0',
  'archive/relay-descriptors/tor/': 'directory 1.0',
  'archive/relay-descriptors/votes/': 'network-status-vote-3 1.0',
  'archive/torperf/': 'torperf 1.0',
  'archive/webstats/': (),
  'recent/bridge-descriptors/extra-infos/': 'bridge-extra-info 1.3',
  'recent/bridge-descriptors/server-descriptors/': 'bridge-server-descriptor 1.2',
  'recent/bridge-descriptors/statuses/': 'bridge-network-status 1.2',
  'recent/exit-lists/': 'tordnsel 1.0',
  'recent/relay-descriptors/bandwidths/': 'bandwidth-file 1.0',
  'recent/relay-descriptors/consensuses/': 'network-status-consensus-3 1.0',
  'recent/relay-descriptors/extra-infos/': 'extra-info 1.0',
  'recent/relay-descriptors/microdescs/consensus-microdesc/': 'network-status-microdesc-consensus-3 1.0',
  'recent/relay-descriptors/microdescs/micro/': 'microdescriptor 1.0',
  'recent/relay-descriptors/server-descriptors/': 'server-descriptor 1.0',
  'recent/relay-descriptors/votes/': 'network-status-vote-3 1.0',
  'recent/torperf/': 'torperf 1.1',
  'recent/webstats/': (),
}


def _download(url, compression, timeout, retries):
  """
  Download from the given url.

  :param str url: uncompressed url to download from
  :param descriptor.Compression compression: decompression type
  :param int timeout: timeout when connection becomes idle, no timeout applied
    if **None**
  :param int retires: maximum attempts to impose

  :returns: content of the given url

  :raises:
    * **IOError** if unable to decompress
    * **socket.timeout** if our request timed out
    * **urllib2.URLError** for most request failures

    Note that the urllib2 module may fail with other exception types, in
    which case we'll pass it along.
  """

  start_time = time.time()
  extension = compression.extension if compression not in (None, Compression.PLAINTEXT) else ''

  if not url.endswith(extension):
    url += extension

  try:
    response = urllib.urlopen(url, timeout = timeout).read()
  except:
    exc = sys.exc_info()[1]

    if timeout is not None:
      timeout -= time.time() - start_time

    if retries > 0 and (timeout is None or timeout > 0):
      log.debug("Failed to download from CollecTor at '%s' (%i retries remaining): %s" % (url, retries, exc))
      return _download(url, compression, timeout, retries - 1)
    else:
      log.debug("Failed to download from CollecTor at '%s': %s" % (url, exc))
      raise

  if compression not in (None, Compression.PLAINTEXT):
    try:
      response = compression.decompress(response)
    except Exception as exc:
      raise IOError('Unable to decompress %s response from %s: %s' % (compression, url, exc))

  return stem.util.str_tools._to_unicode(response)


class File(object):
  """
  File within CollecTor.

  :var str path: file path within collector
  :var stem.descriptor.Compression compression: file compression, **None** if
    this cannot be determined
  :var bool tar: **True** if a tarball, **False** otherwise
  :var int size: size of the file

  :var datetime start: beginning of the time range descriptors are for,
    **None** if this cannot be determined
  :var datetime end: ending of the time range descriptors are for,
    **None** if this cannot be determined
  :var datetime last_modified: when the file was last modified
  """

  def __init__(self, path, size, last_modified):
    self.path = path
    self.compression = File._guess_compression(path)
    self.tar = path.endswith('.tar') or '.tar.' in path
    self.size = size

    self.start, self.end = File._guess_time_range(path)
    self.last_modified = datetime.datetime.strptime(last_modified, '%Y-%m-%d %H:%M')

    self._guessed_type = None

  def guess_descriptor_types(self):
    """
    Descriptor @type this file is expected to have based on its path. If unable
    to determine any this tuple is empty.

    :returns: **tuple** with the descriptor types this file is expected to have
    """

    if self._guessed_type is None:
      guessed_type = ()

      for path_prefix, types in COLLECTOR_DESC_TYPES.items():
        if self.path.startswith(path_prefix):
          guessed_type = (types,) if isinstance(types, str) else types
          break

      self._guessed_type = guessed_type

    return self._guessed_type

  @staticmethod
  def _guess_compression(path):
    """
    Determine file comprssion from CollecTor's filename.
    """

    if '.' not in path or path.endswith('.tar'):
      return Compression.PLAINTEXT
    else:
      for compression in (Compression.LZMA, Compression.BZ2, Compression.GZIP):
        if path.endswith(compression.extension):
          return compression

  @staticmethod
  def _guess_time_range(path):
    """
    Attemt to determine the (start, end) time range from CollecTor's filename.
    This provides (None, None) if this cannot be determined.
    """

    year_match = YEAR_DATE.search(path)

    if year_match:
      year, month = map(int, year_match.groups())
      start = datetime.datetime(year, month, 1)

      if month < 12:
        return (start, datetime.datetime(year, month + 1, 1))
      else:
        return (start, datetime.datetime(year + 1, 1, 1))

    sec_match = SEC_DATE.search(path)

    if sec_match:
      # Descriptors in the 'recent/*' section have filenames with second level
      # granularity. Not quite sure why, but since consensus documents are
      # published hourly we'll use that as the delta here.

      start = datetime.datetime.strptime(sec_match.group(1), '%Y-%m-%d-%H-%M-%S')
      return (start, start + datetime.timedelta(seconds = 3600))

    return (None, None)


class CollecTor(object):
  """
  Downloader for descriptors from CollecTor. The contents of CollecTor are
  provided in `an index <https://collector.torproject.org/index/index.json>`_
  that's fetched as required.

  :var descriptor.Compression compression: compression type to
    download from, if undefiled we'll use the best decompression available
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var float timeout: duration before we'll time out our request
  """

  def __init__(self, compression = 'best', retries = 2, timeout = None):
    self.compression = Compression.PLAINTEXT
    self.retries = retries
    self.timeout = timeout

    self._cached_index = None
    self._cached_files = None
    self._cached_index_at = 0

    if compression == 'best':
      for option in (Compression.LZMA, Compression.BZ2, Compression.GZIP):
        if option.available:
          self.compression = option
          break
    elif compression is not None:
      self.compression = compression

  def index(self):
    """
    Provides the archives available in CollecTor.

    :returns: :class:`~stem.descriptor.collector.Index` with the archive
      contents

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures
    """

    if not self._cached_index or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      response = _download(COLLECTOR_URL + 'index/index.json', self.compression, self.timeout, self.retries)
      self._cached_index = json.loads(response)
      self._cached_index_at = time.time()

    return self._cached_index

  def files(self, descriptor_type = None, start = None, end = None):
    """
    Provides files CollecTor presently has, sorted oldest to newest.

    :param str descriptor_type: descriptor type or prefix to retrieve
    :param datetime.datetime start: time range to begin with
    :param datetime.datetime end: time range to end with

    :returns: **list** of :class:`~stem.descriptor.collector.File`

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures
    """

    if not self._cached_files or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      self._cached_files = CollecTor._files(self.index(), [])

    matches = []

    for entry in self._cached_files:
      if start and (entry.start is None or entry.start < start):
        continue
      elif end and (entry.end is None or entry.end > end):
        continue

      if descriptor_type is None or any([desc_type.startswith(descriptor_type) for desc_type in entry.guess_descriptor_types()]):
        matches.append(entry)

    matches.sort(key = lambda x: x.start if x.start else FUTURE)

    return matches

  @staticmethod
  def _files(val, path):
    """
    Provies a mapping of paths to files within the index.

    :param dict val: index hash
    :param list path: path we've transversed into

    :returns: **list** of :class:`~stem.descriptor.collector.File`
    """

    files = []

    if isinstance(val, dict):
      for k, v in val.items():
        if k == 'files':
          for attr in v:
            file_path = '/'.join(path + [attr.get('path')])
            files.append(File(file_path, attr.get('size'), attr.get('last_modified')))
        elif k == 'directories':
          for attr in v:
            files.extend(CollecTor._files(attr, path + [attr.get('path')]))

    return files
