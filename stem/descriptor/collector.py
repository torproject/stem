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
  import stem.descriptor
  import stem.descriptor.collector

  yesterday = datetime.date.today() - datetime.timedelta(1)

  stem.descriptor.collector.download_server_descriptors(
    destination = '~/descriptor_cache',
    start = yesterday,
  ).join()

  for desc in stem.descriptor.parse_file('~/descriptor_cache', descriptor_type = 'server-descriptor 1.0'):
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))

.. versionadded:: 1.8.0
"""

import json
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


def url(resource, compression = Compression.PLAINTEXT):
  """
  Provides CollecTor url for the given resource.

  :param str resource: resource type of the url
  :param descriptor.Compression compression: compression type to
    download from

  :returns: **str** with the CollecTor url
  """

  # TODO: Unsure how to most elegantly map resources to urls. No doubt
  # this'll change as we add more types.

  if resource == 'index':
    path = ('index', 'index.json')
  else:
    raise ValueError("'%s' isn't a recognized resource type" % resource)

  extension = compression.extension if compression not in (None, Compression.PLAINTEXT) else ''
  return COLLECTOR_URL + '/'.join(path) + extension


def _download(url, compression, timeout, retries):
  """
  Download from the given url.

  :param str url: url to download from
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

    :returns: **dict** with the archive contents

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures
    """

    if not self._cached_index or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      response = _download(url('index', self.compression), self.compression, self.timeout, self.retries)
      self._cached_index = json.loads(response)
      self._cached_index_at = time.time()

    return self._cached_index
