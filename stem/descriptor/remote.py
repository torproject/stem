# Copyright 2013, Damian Johnson
# See LICENSE for licensing information

"""
Utilities for retrieving descriptors from directory authorities and mirrors.
This is mostly done through the
:class:`~stem.descriptor.remote.DescriptorDownloader` class, which issues
:class:`~stem.descriptor.remote.Query` to get descriptor content. For
example...

::

  downloader = DescriptorDownloader(
    cache = '/tmp/descriptor_cache',
    use_mirrors = True,
  )

  query = downloader.get_server_descriptors()

  print "Exit Relays:"

  try:
    for desc in query.run():
      if desc.exit_policy.is_exiting_allowed():
        print "  %s (%s)" % (desc.nickname, desc.fingerprint)

    print
    print "Query took %0.2f seconds" % query.runtime
  except Exception as exc:
    print "Unable to query the server descriptors: %s" % query.error

If you don't care about errors then you can also simply iterate over the query
itself...

::

  for desc in downloader.get_server_descriptors():
    if desc.exit_policy.is_exiting_allowed():
      print "  %s (%s)" % (desc.nickname, desc.fingerprint)
"""

import io
import random
import sys
import threading
import time
import urllib2

import stem.descriptor

# Tor directory authorities as of commit f631b73 (7/4/13). This should only
# include authorities with 'v3ident':
#
# https://gitweb.torproject.org/tor.git/blob/f631b73:/src/or/config.c#l816

DIRECTORY_AUTHORITIES = {
  'moria1': ('128.31.0.39', 9131),
  'tor26': ('86.59.21.38', 80),
  'dizum': ('194.109.206.212', 80),
  'turtles': ('76.73.17.194', 9030),
  'gabelmoo': ('212.112.245.170', 80),
  'dannenberg': ('193.23.244.244', 80),
  'urras': ('208.83.223.34', 443),
  'maatuska': ('171.25.193.9', 443),
  'Faravahar': ('154.35.32.5', 80),
}


class Query(object):
  """
  Asynchronous request for descriptor content from a directory authority or
  mirror. The caller can block on the response by either calling
  :func:~stem.descriptor.remote.run: or iterating over our descriptor content.

  :var str address: address of the authority or mirror we're querying
  :var int port: directory port we're querying
  :var str resource: resource being fetched, such as '/tor/status-vote/current/consensus.z'

  :var Exception error: exception if a problem occured
  :var bool is_done: flag that indicates if our request has finished
  :var str descriptor_type: type of descriptors being fetched, see :func:`~stem.descriptor.__init__.parse_file`

  :var float start_time: unix timestamp when we first started running
  :var float timeout: duration before we'll time out our request
  :var float runtime: time our query took, this is **None** if it's not yet finished
  """

  def __init__(self, address, port, resource, descriptor_type, timeout = None, start = True):
    self.address = address
    self.port = port
    self.resource = resource

    self.error = None
    self.is_done = False
    self.descriptor_type = descriptor_type

    self.start_time = None
    self.timeout = timeout
    self.runtime = None

    self._downloader_thread = None
    self._downloader_thread_lock = threading.RLock()

    self._results = None  # descriptor iterator

    if start:
      self.start()

  def get_url(self):
    """
    Provides the url being queried.

    :returns: **str** for the url being queried by this request
    """

    return "http://%s:%i/%s" % (self.address, self.port, self.resource.lstrip('/'))

  def start(self):
    """
    Starts downloading the scriptors if we haven't started already.
    """

    with self._downloader_thread_lock:
      if self._downloader_thread is None:
        self._downloader_thread = threading.Thread(target = self._download_descriptors, name="Descriptor Query")
        self._downloader_thread.setDaemon(True)
        self._downloader_thread.start()

  def run(self, suppress = False):
    """
    Blocks until our request is complete then provides the descriptors. If we
    haven't yet started our request then this does so.

    :param bool suppress: avoids raising exceptions if **True**

    :returns: iterator for the requested :class:`~stem.descriptor.__init__.Descriptor` instances

    :raises:
      Using the iterator can fail with the following if **suppress** is
      **False**...

        * **ValueError** if the descriptor contents is malformed
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures

      Note that the urllib2 module may fail with other exception types, in
      which case we'll pass it along.
    """

    with self._downloader_thread_lock:
      self.start()
      self._downloader_thread.join()

      if self.error:
        if not suppress:
          raise self.error
      else:
        if self._results is None:
          if not suppress:
            raise ValueError('BUG: _download_descriptors() finished without either results or an error')

          return

        try:
          for desc in self._results:
            yield desc
        except ValueError as exc:
          self.error = exc

          if not suppress:
            raise self.error

  def __iter__(self):
    for desc in self.run(True):
      yield desc

  def _download_descriptors(self):
    try:
      self.start_time = time.time()
      response = urllib2.urlopen(self.get_url(), timeout = self.timeout)
      self.runtime = time.time() - self.start_time

      # This sucks. We need to read the full response into memory before
      # processing the content. This is because urllib2 returns a 'file like'
      # object that lacks tell() or seek(). Hence we need to read it into our
      # own buffer that does support these.

      response = io.BytesIO(response.read().strip())

      self._results = stem.descriptor.parse_file(response, self.descriptor_type)
    except:
      self.error = sys.exc_info()[1]
    finally:
      self.is_done = True


class DescriptorDownloader(object):
  """
  Configurable class through which descriptors can be downloaded. This provides
  caching, retries, and other capabilities to make downloading descriptors easy
  and efficient.

  Queries can be made in either a blocking or non-blocking fashion. If
  non-blocking then retries cannot be performed (since we do not know at the
  time of the request if it succeeded or failed).

  For more advanced use cases you can use the
  :class:`~stem.descriptor.remote.Query` class directly.

  :var bool block: blocks until requests have been concluded if **True**,
    otherwise provides the query as soon as its been issued
  :var int retries: number of times to attempt the request if it fails
  :var float timeout: duration before we'll time out our request, no timeout is
    applied if **None**
  :var bool start_when_requested: issues requests when our methods are called
    if **True**, otherwise provides non-running
    :class:`~stem.descriptor.remote.Query` instances
  :var bool fall_back_to_authority: when retrying request issues the last
    request to a directory authority if **True**
  """

  def __init__(self, block = True, retries = 2, timeout = None, start_when_requested = True, fall_back_to_authority = True):
    self.block = block
    self.retries = retries
    self.timeout = timeout
    self.start_when_requested = start_when_requested
    self.fall_back_to_authority = fall_back_to_authority
    self._directories = DIRECTORY_AUTHORITIES.values()

  def _query(self, resource, descriptor_type, retries):
    """
    Issues a request for the given resource.
    """

    if self.fall_back_to_authority and retries == 0:
      address, dirport = random.choice(DIRECTORY_AUTHORITIES.values())
    else:
      address, dirport = random.choice(self._directories)

    query = Query(
      address,
      dirport,
      resource,
      descriptor_type,
      timeout = self.timeout,
      start = self.start_when_requested,
    )

    if self.block:
      query.run(True)

      if query.error and retries > 0:
        return self.query(resource, descriptor_type, retries - 1)

    return query
