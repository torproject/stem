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

  yesterday = datetime.datetime.utcnow() - datetime.timedelta(days = 1)

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

  yesterday = datetime.datetime.utcnow() - datetime.timedelta(days = 1)
  path = os.path.expanduser('~/descriptor_cache/server_desc_today')

  with open(path, 'wb') as cache_file:
    for desc in stem.descriptor.collector.get_server_descriptors(start = yesterday):
      cache_file.write(desc.get_bytes())

  # then later...

  for desc in stem.descriptor.parse_file(path, descriptor_type = 'server-descriptor 1.0'):
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))

::

  get_instance - Provides a singleton CollecTor used for...
    +- get_server_descriptors - published server descriptors

  File - Individual file residing within CollecTor
    |- read - provides descriptors from this file
    +- download - download this file to disk

  CollecTor - Downloader for descriptors from CollecTor
    |- get_server_descriptors - published server descriptors
    |
    |- index - metadata for content available from CollecTor
    +- files - files available from CollecTor

.. versionadded:: 1.8.0
"""

import datetime
import json
import os
import re
import shutil
import tempfile
import time

import stem.util.connection
import stem.util.str_tools

from stem.descriptor import Compression, parse_file

COLLECTOR_URL = 'https://collector.torproject.org/'
REFRESH_INDEX_RATE = 3600  # get new index if cached copy is an hour old
SINGLETON_COLLECTOR = None

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


def get_instance():
  """
  Provides the singleton :class:`~stem.descriptor.collector.CollecTor`
  used for this module's shorthand functions.

  :returns: singleton :class:`~stem.descriptor.collector.CollecTor` instance
  """

  global SINGLETON_COLLECTOR

  if SINGLETON_COLLECTOR is None:
    SINGLETON_COLLECTOR = CollecTor()

  return SINGLETON_COLLECTOR


def get_server_descriptors(start = None, end = None, cache_to = None, timeout = None, retries = 3):
  """
  Provides server descriptors for the given time range, sorted oldest to
  newest.

  :param datetime.datetime start: time range to begin with
  :param datetime.datetime end: time range to end with
  :param str cache_to: directory to cache archives into, if an archive is
    available here it is not downloaded
  :param int timeout: timeout for downloading each individual archive when the
    connection becomes idle, no timeout applied if **None**
  :param int retires: maximum attempts to impose on a per-archive basis

  :returns: **iterator** of
    :class:`~stem.descriptor.server_descriptor.ServerDescriptor` for the given
    time range

  :raises: :class:`~stem.DownloadFailed` if the download fails
  """

  for f in get_instance().files('server-descriptor', start, end):
    for desc in f.read(cache_to, timeout = timeout, retries = retries):
      yield desc


class File(object):
  """
  File within CollecTor.

  :var str path: file path within collector
  :var stem.descriptor.Compression compression: file compression, **None** if
    this cannot be determined
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
    self.size = size

    self.start, self.end = File._guess_time_range(path)
    self.last_modified = datetime.datetime.strptime(last_modified, '%Y-%m-%d %H:%M')

    self._guessed_type = File._guess_descriptor_types(path)
    self._downloaded_to = None  # location we last downloaded to

  def read(self, directory = None, descriptor_type = None, timeout = None, retries = 3):
    """
    Provides descriptors from this archive. Descriptors are downloaded or read
    from disk as follows...

    * If this file has already been downloaded through
      :func:`~stem.descriptor.collector.CollecTor.download' these descriptors
      are read from disk.

    * If a **directory** argument is provided and the file is already present
      these descriptors are read from disk.

    * If a **directory** argument is provided and the file is not present the
      file is downloaded this location then read.

    * If the file has neither been downloaded and no **directory** argument
      is provided then the file is downloaded to a temporary directory that's
      deleted after it is read.

    :param str directory: destination to download into
    :param str descriptor_type: `descriptor type
      <https://metrics.torproject.org/collector.html#data-formats>`_, this is
      guessed if not provided
    :param int timeout: timeout when connection becomes idle, no timeout
      applied if **None**
    :param int retires: maximum attempts to impose

    :returns: iterator for :class:`~stem.descriptor.__init__.Descriptor`
      instances in the file

    :raises:
      * **ValueError** if unable to determine the descirptor type
      * **TypeError** if we cannot parse this descriptor type
      * :class:`~stem.DownloadFailed` if the download fails
    """

    if descriptor_type is None:
      if not self._guessed_type:
        raise ValueError("Unable to determine this file's descriptor type")
      elif len(self._guessed_type) > 1:
        raise ValueError("Unable to determine disambiguate file's descriptor type from %s" % ', '.join(self._guessed_type))

      descriptor_type = self._guessed_type[0]

    if directory is None:
      if self._downloaded_to and os.path.exists(self._downloaded_to):
        directory = os.path.dirname(self._downloaded_to)
      else:
        # TODO: The following can be replaced with simpler usage of
        # tempfile.TemporaryDirectory when we drop python 2.x support.

        tmp_directory = tempfile.mkdtemp()

        for desc in self.read(tmp_directory, descriptor_type, timeout, retries):
          yield desc

        shutil.rmtree(tmp_directory)

        return

    # TODO: the following will not work if the tar contains multiple types or a type we do not support

    path = self.download(directory, True, timeout, retries)

    for desc in parse_file(path, descriptor_type):
      yield desc

  def download(self, directory, decompress = True, timeout = None, retries = 3):
    """
    Downloads this file to the given location. If a file already exists this is
    a no-op.

    :param str directory: destination to download into
    :param bool decompress: decompress written file
    :param int timeout: timeout when connection becomes idle, no timeout
      applied if **None**
    :param int retires: maximum attempts to impose

    :returns: **str** with the path we downloaded to

    :raises: :class:`~stem.DownloadFailed` if the download fails
    """

    # TODO: If checksums get added to the index we should replace
    # the path check below to verify that...
    #
    #   https://trac.torproject.org/projects/tor/ticket/31204

    filename = self.path.split('/')[-1]

    if self.compression != Compression.PLAINTEXT and decompress:
      filename = filename.rsplit('.', 1)[0]

    path = os.path.join(directory, filename)

    if not os.path.exists(directory):
      os.makedirs(directory)
    elif os.path.exists(path):
      return path  # file already exists

    response = stem.util.connection.download(COLLECTOR_URL + self.path, timeout, retries)

    if decompress:
      response = self.compression.decompress(response)

    with open(path, 'wb') as output_file:
      output_file.write(response)

    self._downloaded_to = path
    return path

  @staticmethod
  def _guess_descriptor_types(path):
    """
    Descriptor @type this file is expected to have based on its path. If unable
    to determine any this tuple is empty.

    Hopefully this will be replaced with an explicit value in the future:

      https://trac.torproject.org/projects/tor/ticket/31204

    :returns: **tuple** with the descriptor types this file is expected to have
    """

    for path_prefix, types in COLLECTOR_DESC_TYPES.items():
      if path.startswith(path_prefix):
        return (types,) if isinstance(types, str) else types

    return ()

  @staticmethod
  def _guess_compression(path):
    """
    Determine file comprssion from CollecTor's filename.
    """

    for compression in (Compression.LZMA, Compression.BZ2, Compression.GZIP):
      if path.endswith(compression.extension):
        return compression

    return Compression.PLAINTEXT

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

  :var int retries: number of times to attempt the request if downloading it
    fails
  :var float timeout: duration before we'll time out our request
  """

  def __init__(self, retries = 2, timeout = None):
    self.retries = retries
    self.timeout = timeout

    self._cached_index = None
    self._cached_files = None
    self._cached_index_at = 0

  def index(self, compression = 'best'):
    """
    Provides the archives available in CollecTor.

    :param descriptor.Compression compression: compression type to
      download from, if undefiled we'll use the best decompression available

    :returns: :class:`~stem.descriptor.collector.Index` with the archive
      contents

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * :class:`~stem.DownloadFailed` if the download fails
    """

    if not self._cached_index or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      if compression == 'best':
        for option in (Compression.LZMA, Compression.BZ2, Compression.GZIP, Compression.PLAINTEXT):
          if option.available:
            compression = option
            break
      elif compression is None:
        compression = Compression.PLAINTEXT

      extension = compression.extension if compression != Compression.PLAINTEXT else ''
      url = COLLECTOR_URL + 'index/index.json' + extension
      response = compression.decompress(stem.util.connection.download(url, self.timeout, self.retries))

      self._cached_index = json.loads(stem.util.str_tools._to_unicode(response))
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
        * :class:`~stem.DownloadFailed` if the download fails
    """

    if not self._cached_files or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      self._cached_files = sorted(CollecTor._files(self.index(), []), key = lambda x: x.start if x.start else FUTURE)

    matches = []

    for f in self._cached_files:
      if start and (f.start is None or f.start < start):
        continue
      elif end and (f.end is None or f.end > end):
        continue

      if descriptor_type is None or any([desc_type.startswith(descriptor_type) for desc_type in f._guessed_type]):
        matches.append(f)

    return matches

  @staticmethod
  def _files(val, path):
    """
    Recursively provies files within the index.

    :param dict val: index hash
    :param list path: path we've transversed into

    :returns: **list** of :class:`~stem.descriptor.collector.File`
    """

    if not isinstance(val, dict):
      return []  # leaf node without any files

    files = []

    for k, v in val.items():
      if k == 'files':
        for attr in v:
          file_path = '/'.join(path + [attr.get('path')])
          files.append(File(file_path, attr.get('size'), attr.get('last_modified')))
      elif k == 'directories':
        for attr in v:
          files.extend(CollecTor._files(attr, path + [attr.get('path')]))

    return files
