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

COLLECTOR_URL = 'https://collector.torproject.org/'
REFRESH_INDEX_RATE = 3600  # get new index if cached copy is an hour old


class Compression(object):
  """
  Compression method supported by CollecTor.

  :var bool available: **True** if this method of decryption is available,
    **False** otherwise
  :var str extension: file extension of this compression
  """

  def __init__(self, module, extension):
    # Compression modules are optional. Usually gzip and bz2 are available, but
    # they might be missing if compiling python yourself. As for lzma it was
    # added in python 3.3.

    try:
      self._module = __import__(module)
      self.available = True
    except ImportError:
      self._module = None
      self.available = False

    self.extension = extension
    self._module_name = module

  def decompress(self, content):
    """
    Decompresses the given content via this method.

    :param bytes content: content to be decompressed

    :returns: **bytes** with the decompressed content

    :raises:
      If unable to decompress this provide...

      * **IOError** if content isn't compressed with this
      * **ImportError** if this method if decompression is unavalable
    """

    if not self.available:
      raise ImportError("'%s' decompression module is unavailable" % self)

    if self._module_name == 'gzip':
      if stem.prereq.is_python_3():
        return self._module.decompress(content)
      else:
        # prior to python 3.2 gzip only had GzipFile
        return self._module.GzipFile(fileobj = io.BytesIO(content)).read()
    elif self._module_name == 'bz2':
      return self._module.decompress(content)
    elif self._module_name == 'lzma':
      return self._module.decompress(content)
    else:
      raise ImportError('BUG: No implementation for %s decompression' % self)

  def __str__(self):
    return self._module_name


GZIP = Compression('gzip', '.gz')
BZ2 = Compression('bz2', '.bz2')
LZMA = Compression('lzma', '.xz')


def url(resource, compression = None):
  """
  Provides CollecTor url for the given resource.

  :param str resource: resource type of the url
  :param descriptor.collector.Compression compression: compression type to
    download from

  :returns: **str** with the CollecTor url
  """

  # TODO: Not yet sure how to most elegantly map resources to urls. No doubt
  # this'll change as we add more types.

  if resource == 'index':
    path = ('index', 'index.json')
  else:
    raise ValueError("'%s' isn't a recognized resource type" % resource)

  suffix = compression.extension if compression else ''
  return ''.join((COLLECTOR_URL, '/'.join(path), suffix))


class CollecTor(object):
  """
  Downloader for descriptors from CollecTor. The contents of CollecTor are
  provided in `an index <https://collector.torproject.org/index/index.json>`_
  that's fetched as required.

  :var descriptor.collector.Compression compression: compression type to
    download from, if undefiled we'll use the best decompression available
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var float timeout: duration before we'll time out our request
  """

  def __init__(self, compression = 'best', retries = 2, timeout = None):
    if compression == 'best':
      self.compression = None

      for option in (LZMA, BZ2, GZIP):
        if option.available:
          self.compression = option
          break
    else:
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

        * **ValueError** if json is malformed
        * **IOError** if unable to decompress
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures
    """

    if not self._cached_index or time.time() - self._cached_index_at >= REFRESH_INDEX_RATE:
      # TODO: add retry support

      response = urllib.urlopen(url('index', self.compression), timeout = self.timeout).read()

      if self.compression:
        try:
          response = self.compression.decompress(response)
        except Exception as exc:
          raise IOError('Unable to decompress response as %s: %s' % (self.compression, exc))

      self._cached_index = json.loads(stem.util.str_tools._to_unicode(response))
      self._cached_index_at = time.time()

    return self._cached_index
