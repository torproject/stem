# Copyright 2017, Damian Johnson and The Tor Project
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

  collector = stem.descriptor.collector.CollecTor()
  yesterday = datetime.date.today() - datetime.timedelta(1)

  # provide yesterday's exits

  for desc in collector.get_server_descriptors(start = yesterday):
    if desc.exit_policy.is_exiting_allowed():
      print '  %s (%s)' % (desc.nickname, desc.fingerprint)

... or download the descriptors to disk and read them later.

::

  import datetime
  import stem.descriptor.collector
  import stem.descriptor.reader

  collector = stem.descriptor.collector.CollecTor()
  yesterday = datetime.date.today() - datetime.timedelta(1)

  collector.download_server_descriptors(
    destination = '~/descriptor_cache',
    start = yesterday,
  ).join()

  reader = stem.descriptor.reader.DescriptorReader('~/descriptor_cache')

  for desc in reader:
    if desc.exit_policy.is_exiting_allowed():
      print '  %s (%s)' % (desc.nickname, desc.fingerprint)

.. versionadded:: 1.7.0
"""

import gzip
import io
import json
import time

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

import stem.prereq
import stem.util.enum
import stem.util.str_tools

Compression = stem.util.enum.Enum('NONE', 'BZ2', 'GZ', 'XZ')

COLLECTOR_URL = 'https://collector.torproject.org/'
REFRESH_INDEX_RATE = 3600  # get new index if cached copy is an hour old

COMPRESSION_SUFFIX = {
  Compression.NONE: '',
  Compression.BZ2: '.bz2',
  Compression.GZ: '.gz',
  Compression.XZ: '.xz',
}


def url(resource, compression = Compression.NONE):
  """
  Provides CollecTor url for the given resource.

  :param str resource: resource type of the url
  :param descriptor.collector.Compression compression: compression type to
    download from

  :returns: **str** with the CollecTor url
  """

  if compression not in COMPRESSION_SUFFIX:
    raise ValueError("'%s' isn't a compression enumeration" % compression)

  # TODO: Not yet sure how to most elegantly map resources to urls. No doubt
  # this'll change as we add more types.

  if resource == 'index':
    path = ('index', 'index.json')
  else:
    raise ValueError("'%s' isn't a recognized resource type" % resource)

  return ''.join((COLLECTOR_URL, '/'.join(path), COMPRESSION_SUFFIX[compression]))


class CollecTor(object):
  """
  Downloader for descriptors from CollecTor. The contents of CollecTor are
  provided in `an index <https://collector.torproject.org/index/index.json>`_
  that's fetched as required.

  :var descriptor.collector.Compression compression: compression type to
    download from
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var float timeout: duration before we'll time out our request
  """

  def __init__(self, compression = Compression.XZ, retries = 2, timeout = None):
    self.compression = compression
    self.retries = retries
    self.timeout = timeout

    self._cached_index = None
    self._cached_index_at = 0

  def index(self):
    """
    Provides the archives available in CollecTor.

    :returns: **dict** with the archive contents

    :raises:
      If unable to retrieve the index this provide...

        * **ValueError** if the index is malformed
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures
    """

    if not self._cached_index or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      response = urllib.urlopen(url('index', self.compression), timeout = self.timeout).read()

      # TODO: add compression and retry support

      if self.compression == Compression.GZ:
        if stem.prereq.is_python_3():
          response = gzip.decompress(response)
        else:
          # prior to python 3.2 gzip only had GzipFile
          response = gzip.GzipFile(fileobj = io.BytesIO(response)).read()

      self._cached_index = json.loads(stem.util.str_tools._to_unicode(response))
      self._cached_index_at = time.time()

    return self._cached_index
