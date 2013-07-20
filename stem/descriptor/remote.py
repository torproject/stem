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

from stem import Flag
from stem.util import log

# Tor has a limit on the number of descriptors we can fetch explicitly by their
# fingerprint or hashes due to the url lenght of squid proxies.

MAX_DESCRIPTOR_BATCH_SIZE = 96
MAX_MICRODESCRIPTOR_BATCH_SIZE = 92

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

  :var str resource: resource being fetched, such as '/tor/status-vote/current/consensus.z'
  :var str descriptor_type: type of descriptors being fetched, see
    :func:`~stem.descriptor.__init__.parse_file`

  :var list endpoints: (address, dirport) tuples of the authority or mirror
    we're querying, this uses authorities if undefined
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var bool fall_back_to_authority: when retrying request issues the last
    request to a directory authority if **True**

  :var Exception error: exception if a problem occured
  :var bool is_done: flag that indicates if our request has finished
  :var str download_url: last url used to download the descriptor, this is
    unset until we've actually made a download attempt

  :var float start_time: unix timestamp when we first started running
  :var float timeout: duration before we'll time out our request
  :var float runtime: time our query took, this is **None** if it's not yet
    finished

  :var bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :var stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse the :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  """

  def __init__(self, resource, descriptor_type, endpoints = None, retries = 2, fall_back_to_authority = True, timeout = None, start = True, validate = True, document_handler = stem.descriptor.DocumentHandler.ENTRIES):
    self.resource = resource
    self.descriptor_type = descriptor_type

    self.endpoints = endpoints if endpoints else []
    self.retries = retries
    self.fall_back_to_authority = fall_back_to_authority

    self.error = None
    self.is_done = False
    self.download_url = None

    self.start_time = None
    self.timeout = timeout
    self.runtime = None

    self.validate = validate
    self.document_handler = document_handler

    self._downloader_thread = None
    self._downloader_thread_lock = threading.RLock()

    self._results = None  # descriptor iterator

    if start:
      self.start()

  def pick_url(self, use_authority = False):
    """
    Provides a url that can be queried. If we have multiple endpoints then one
    will be picked randomly.

    :param bool use_authority: ignores our endpoints and uses a directory
      authority instead

    :returns: **str** for the url being queried by this request
    """

    if use_authority or not self.endpoints:
      address, dirport = random.choice(DIRECTORY_AUTHORITIES.values())
    else:
      address, dirport = random.choice(self.endpoints)

    return "http://%s:%i/%s" % (address, dirport, self.resource.lstrip('/'))

  def start(self):
    """
    Starts downloading the scriptors if we haven't started already.
    """

    with self._downloader_thread_lock:
      if self._downloader_thread is None:
        self._downloader_thread = threading.Thread(target = self._download_descriptors, name="Descriptor Query", args = (self.retries,))
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
          # encountered a parsing error

          self.error = exc

          if not suppress:
            raise self.error

  def __iter__(self):
    for desc in self.run(True):
      yield desc

  def _download_descriptors(self, retries):
    try:
      use_authority = retries == 0 and self.fall_back_to_authority
      self.download_url = self.pick_url(use_authority)

      self.start_time = time.time()
      response = urllib2.urlopen(self.download_url, timeout = self.timeout)
      self.runtime = time.time() - self.start_time

      # This sucks. We need to read the full response into memory before
      # processing the content. This is because urllib2 returns a 'file like'
      # object that lacks tell() or seek(). Hence we need to read it into our
      # own buffer that does support these.

      response = io.BytesIO(response.read().strip())

      self._results = stem.descriptor.parse_file(response, self.descriptor_type, validate = self.validate, document_handler = self.document_handler)
      log.trace("Descriptors retrieved from '%s' in %0.2fs" % (self.download_url, self.runtime))
    except:
      exc = sys.exc_info()[1]

      if retries > 0:
        log.debug("Unable to download descriptors from '%s' (%i retries remaining): %s" % (self.download_url, retries, exc))
        return self._download_descriptors(retries - 1)
      else:
        log.debug("Unable to download descriptors from '%s': %s" % (self.download_url, exc))
        self.error = exc
    finally:
      self.is_done = True


class DescriptorDownloader(object):
  """
  Configurable class through which descriptors can be downloaded. This provides
  caching, retries, and other capabilities to make downloading descriptors easy
  and efficient.

  For more advanced use cases you can use the
  :class:`~stem.descriptor.remote.Query` class directly.

  :var int retries: number of times to attempt the request if it fails
  :var float timeout: duration before we'll time out our request, no timeout is
    applied if **None**
  :var bool use_mirrors: downloads the present consensus and uses the directory
    mirrors to fetch future requests, this fails silently if the consensus
    cannot be downloaded
  :var bool start_when_requested: issues requests when our methods are called
    if **True**, otherwise provides non-running
    :class:`~stem.descriptor.remote.Query` instances
  :var bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :var bool fall_back_to_authority: when retrying request issues the last
    request to a directory authority if **True**
  """

  def __init__(self, retries = 2, use_mirrors = False, fall_back_to_authority = True, timeout = None, start_when_requested = True, validate = True):
    self.retries = retries
    self.timeout = timeout
    self.start_when_requested = start_when_requested
    self.fall_back_to_authority = fall_back_to_authority
    self.validate = validate
    self._endpoints = DIRECTORY_AUTHORITIES.values()

    if use_mirrors:
      try:
        start_time = time.time()
        self.use_directory_mirrors()
        log.debug("Retrieve directory mirrors (took %0.2fs)" % (time.time() - start_time))
      except Exception, exc:
        log.debug("Unable to retrieve directory mirrors: %s" % exc)

  def use_directory_mirrors(self):
    """
    Downloads the present consensus and configures ourselves to use directory
    mirrors, in addition to authorities.

    :raises: **Exception** if unable to determine the directory mirrors
    """

    new_endpoints = set(DIRECTORY_AUTHORITIES.values())

    query = self.get_consensus()
    query.run()  # running explicitly so we'll raise errors

    for desc in query:
      if Flag.V2DIR in desc.flags:
        new_endpoints.add((desc.address, desc.dir_port))

    # we need our endpoints to be a list rather than set for random.choice()

    self._endpoints = list(new_endpoints)

  def get_server_descriptors(self, fingerprints = None):
    """
    Provides the server descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors in the present
    consensus.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**

    :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/server/all'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_DESCRIPTOR_BATCH_SIZE:
        raise ValueError("Unable to request more than %i descriptors at a time by their fingerprints" % MAX_DESCRIPTOR_BATCH_SIZE)

      resource = '/tor/server/fp/%s' % '+'.join(fingerprints)

    return self._query(resource, 'server-descriptor 1.0')

  def get_extrainfo_descriptors(self, fingerprints = None):
    """
    Provides the extrainfo descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors in the present
    consensus.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**

    :returns: :class:`~stem.descriptor.remote.Query` for the extrainfo descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/extra/all'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_DESCRIPTOR_BATCH_SIZE:
        raise ValueError("Unable to request more than %i descriptors at a time by their fingerprints" % MAX_DESCRIPTOR_BATCH_SIZE)

      resource = '/tor/extra/fp/%s' % '+'.join(fingerprints)

    return self._query(resource, 'extra-info 1.0')

  def get_microdescriptors(self, hashes):
    """
    Provides the microdescriptors with the given hashes. To get these see the
    'microdescriptor_hashes' attribute of
    :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`. Note
    that these are only provided via a microdescriptor consensus (such as
    'cached-microdesc-consensus' in your data directory).

    :param str,list hashes: microdescriptor hash or list of hashes to be
      retrieved

    :returns: :class:`~stem.descriptor.remote.Query` for the microdescriptors

    :raises: **ValueError** if we request more than 92 microdescriptors by their
      hashes (this is due to a limit on the url length by squid proxies).
    """

    if isinstance(hashes, str):
      hashes = [hashes]

    if len(hashes) > MAX_MICRODESCRIPTOR_BATCH_SIZE:
      raise ValueError("Unable to request more than %i microdescriptors at a time by their hashes" % MAX_MICRODESCRIPTOR_BATCH_SIZE)

    resource = '/tor/micro/d/%s' % '-'.join(hashes)

    return self._query(resource, 'microdescriptor 1.0')

  def get_consensus(self, document_handler = stem.descriptor.DocumentHandler.ENTRIES, authority_v3ident = None):
    """
    Provides the present router status entries.

    :param stem.descriptor.__init__.DocumentHandler document_handler: method in
      which to parse the :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`
    :param str authority_v3ident: fingerprint of the authority key for which
      to get the consensus, see `'v3ident' in tor's config.c
      <https://gitweb.torproject.org/tor.git/blob/f631b73:/src/or/config.c#l816>`_
      for the values.

    :returns: :class:`~stem.descriptor.remote.Query` for the router status
      entries
    """

    resource = '/tor/status-vote/current/consensus'

    if authority_v3ident:
      resource += '/%s' % authority_v3ident

    return self._query(
      resource,
      'network-status-consensus-3 1.0',
      document_handler = document_handler,
    )

  def _query(self, resource, descriptor_type, document_handler = stem.descriptor.DocumentHandler.ENTRIES):
    """
    Issues a request for the given resource.
    """

    log.trace("Retrieving descriptors (resource: %s, type: %s)" % (resource, descriptor_type))

    return Query(
      resource,
      descriptor_type,
      endpoints = self._endpoints,
      retries = self.retries,
      fall_back_to_authority = self.fall_back_to_authority,
      timeout = self.timeout,
      start = self.start_when_requested,
      validate = self.validate,
      document_handler = document_handler,
    )
