# Copyright 2013-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for remotely retrieving descriptors from directory authorities and
mirrors. This is the simplest method for getting current tor descriptor
information...

::

  import stem.descriptor.remote

  for desc in stem.descriptor.remote.get_server_descriptors():
    if desc.exit_policy.is_exiting_allowed():
      print '  %s (%s)' % (desc.nickname, desc.fingerprint)

More custom downloading behavior can be done through the
:class:`~stem.descriptor.remote.DescriptorDownloader` class, which issues
:class:`~stem.descriptor.remote.Query` instances to get you descriptor
content. For example...

::

  from stem.descriptor.remote import DescriptorDownloader

  downloader = DescriptorDownloader(
    use_mirrors = True,
    timeout = 10,
  )

  query = downloader.get_server_descriptors()

  print 'Exit Relays:'

  try:
    for desc in query.run():
      if desc.exit_policy.is_exiting_allowed():
        print '  %s (%s)' % (desc.nickname, desc.fingerprint)

    print
    print 'Query took %0.2f seconds' % query.runtime
  except Exception as exc:
    print 'Unable to retrieve the server descriptors: %s' % exc

::

  get_instance - Provides a singleton DescriptorDownloader used for...
    |- get_server_descriptors - provides present server descriptors
    |- get_extrainfo_descriptors - provides present extrainfo descriptors
    +- get_consensus - provides the present consensus or router status entries

  get_authorities - Provides tor directory information.

  Directory - Relay we can retrieve directory information from
    |- DirectoryAuthority - Information about a tor directory authority
    +- FallbackDirectory - Directory mirror tor uses when authories are unavailable
        |- from_cache - Provides fallback directories cached with Stem.
        +- from_remote - Retrieves fallback directories remotely from tor's latest commit.

  Query - Asynchronous request to download tor descriptors
    |- start - issues the query if it isn't already running
    +- run - blocks until the request is finished and provides the results

  DescriptorDownloader - Configurable class for issuing queries
    |- use_directory_mirrors - use directory mirrors to download future descriptors
    |- get_server_descriptors - provides present server descriptors
    |- get_extrainfo_descriptors - provides present extrainfo descriptors
    |- get_consensus - provides the present consensus or router status entries
    |- get_key_certificates - provides present authority key certificates
    +- query - request an arbitrary descriptor resource

.. versionadded:: 1.1.0

.. data:: MAX_FINGERPRINTS

  Maximum number of descriptors that can requested at a time by their
  fingerprints.

.. data:: MAX_MICRODESCRIPTOR_HASHES

  Maximum number of microdescriptors that can requested at a time by their
  hashes.
"""

import io
import os
import random
import re
import sys
import threading
import time
import zlib

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

import stem.descriptor

from stem import Flag
from stem.util import _hash_attr, connection, log, str_tools, tor_tools

# Tor has a limited number of descriptors we can fetch explicitly by their
# fingerprint or hashes due to a limit on the url length by squid proxies.

MAX_FINGERPRINTS = 96
MAX_MICRODESCRIPTOR_HASHES = 92

GITWEB_FALLBACK_DIR_URL = 'https://gitweb.torproject.org/tor.git/plain/src/or/fallback_dirs.inc'
CACHE_PATH = os.path.join(os.path.dirname(__file__), 'fallback_directories.cfg')

SINGLETON_DOWNLOADER = None


def get_instance():
  """
  Provides the singleton :class:`~stem.descriptor.remote.DescriptorDownloader`
  used for the following functions...

    * :func:`stem.descriptor.remote.get_server_descriptors`
    * :func:`stem.descriptor.remote.get_extrainfo_descriptors`
    * :func:`stem.descriptor.remote.get_consensus`

  .. versionadded:: 1.5.0

  :returns: singleton :class:`~stem.descriptor.remote.DescriptorDownloader` instance
  """

  global SINGLETON_DOWNLOADER

  if SINGLETON_DOWNLOADER is None:
    SINGLETON_DOWNLOADER = DescriptorDownloader()

  return SINGLETON_DOWNLOADER


def get_server_descriptors(fingerprints = None, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_server_descriptors`
  on our singleton instance.

  .. versionadded:: 1.5.0
  """

  return get_instance().get_server_descriptors(fingerprints, **query_args)


def get_extrainfo_descriptors(fingerprints = None, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_extrainfo_descriptors`
  on our singleton instance.

  .. versionadded:: 1.5.0
  """

  return get_instance().get_extrainfo_descriptors(fingerprints, **query_args)


def get_consensus(authority_v3ident = None, microdescriptor = False, **query_args):
  """
  Shorthand for
  :func:`~stem.descriptor.remote.DescriptorDownloader.get_consensus`
  on our singleton instance.

  .. versionadded:: 1.5.0
  """

  return get_instance().get_consensus(authority_v3ident, microdescriptor, **query_args)


def _guess_descriptor_type(resource):
  # Attempts to determine the descriptor type based on the resource url. This
  # raises a ValueError if the resource isn't recognized.

  if resource.startswith('/tor/server/'):
    return 'server-descriptor 1.0'
  elif resource.startswith('/tor/extra/'):
    return 'extra-info 1.0'
  elif resource.startswith('/tor/micro/'):
    return 'microdescriptor 1.0'
  elif resource.startswith('/tor/status-vote/current/consensus-microdesc'):
    return 'network-status-microdesc-consensus-3 1.0'
  elif resource.startswith('/tor/status-vote/'):
    return 'network-status-consensus-3 1.0'
  elif resource.startswith('/tor/keys/'):
    return 'dir-key-certificate-3 1.0'
  else:
    raise ValueError("Unable to determine the descriptor type for '%s'" % resource)


class Query(object):
  """
  Asynchronous request for descriptor content from a directory authority or
  mirror. These can either be made through the
  :class:`~stem.descriptor.remote.DescriptorDownloader` or directly for more
  advanced usage.

  To block on the response and get results either call
  :func:`~stem.descriptor.remote.Query.run` or iterate over the Query. The
  :func:`~stem.descriptor.remote.Query.run` method pass along any errors that
  arise...

  ::

    from stem.descriptor.remote import Query

    query = Query(
      '/tor/server/all.z',
      block = True,
      timeout = 30,
    )

    print 'Current relays:'

    if not query.error:
      for desc in query:
        print desc.fingerprint
    else:
      print 'Unable to retrieve the server descriptors: %s' % query.error

  ... while iterating fails silently...

  ::

    print 'Current relays:'

    for desc in Query('/tor/server/all.z', 'server-descriptor 1.0'):
      print desc.fingerprint

  In either case exceptions are available via our 'error' attribute.

  Tor provides quite a few different descriptor resources via its directory
  protocol (see section 4.2 and later of the `dir-spec
  <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_).
  Commonly useful ones include...

  =============================================== ===========
  Resource                                        Description
  =============================================== ===========
  /tor/server/all.z                               all present server descriptors
  /tor/server/fp/<fp1>+<fp2>+<fp3>.z              server descriptors with the given fingerprints
  /tor/extra/all.z                                all present extrainfo descriptors
  /tor/extra/fp/<fp1>+<fp2>+<fp3>.z               extrainfo descriptors with the given fingerprints
  /tor/micro/d/<hash1>-<hash2>.z                  microdescriptors with the given hashes
  /tor/status-vote/current/consensus.z            present consensus
  /tor/status-vote/current/consensus-microdesc.z  present microdescriptor consensus
  /tor/keys/all.z                                 key certificates for the authorities
  /tor/keys/fp/<v3ident1>+<v3ident2>.z            key certificates for specific authorities
  =============================================== ===========

  The '.z' suffix can be excluded to get a plaintext rather than compressed
  response. Compression is handled transparently, so this shouldn't matter to
  the caller.

  :var str resource: resource being fetched, such as '/tor/server/all.z'
  :var str descriptor_type: type of descriptors being fetched (for options see
    :func:`~stem.descriptor.__init__.parse_file`), this is guessed from the
    resource if **None**

  :var list endpoints: (address, dirport) tuples of the authority or mirror
    we're querying, this uses authorities if undefined
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var bool fall_back_to_authority: when retrying request issues the last
    request to a directory authority if **True**

  :var str content: downloaded descriptor content
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
    which to parse a :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :var dict kwargs: additional arguments for the descriptor constructor

  :param bool start: start making the request when constructed (default is **True**)
  :param bool block: only return after the request has been completed, this is
    the same as running **query.run(True)** (default is **False**)
  """

  def __init__(self, resource, descriptor_type = None, endpoints = None, retries = 2, fall_back_to_authority = False, timeout = None, start = True, block = False, validate = False, document_handler = stem.descriptor.DocumentHandler.ENTRIES, **kwargs):
    if not resource.startswith('/'):
      raise ValueError("Resources should start with a '/': %s" % resource)

    self.resource = resource

    if descriptor_type:
      self.descriptor_type = descriptor_type
    else:
      self.descriptor_type = _guess_descriptor_type(resource)

    self.endpoints = endpoints if endpoints else []
    self.retries = retries
    self.fall_back_to_authority = fall_back_to_authority

    self.content = None
    self.error = None
    self.is_done = False
    self.download_url = None

    self.start_time = None
    self.timeout = timeout
    self.runtime = None

    self.validate = validate
    self.document_handler = document_handler
    self.kwargs = kwargs

    self._downloader_thread = None
    self._downloader_thread_lock = threading.RLock()

    if start:
      self.start()

    if block:
      self.run(True)

  def start(self):
    """
    Starts downloading the scriptors if we haven't started already.
    """

    with self._downloader_thread_lock:
      if self._downloader_thread is None:
        self._downloader_thread = threading.Thread(
          name = 'Descriptor Query',
          target = self._download_descriptors,
          args = (self.retries,)
        )

        self._downloader_thread.setDaemon(True)
        self._downloader_thread.start()

  def run(self, suppress = False):
    """
    Blocks until our request is complete then provides the descriptors. If we
    haven't yet started our request then this does so.

    :param bool suppress: avoids raising exceptions if **True**

    :returns: list for the requested :class:`~stem.descriptor.__init__.Descriptor` instances

    :raises:
      Using the iterator can fail with the following if **suppress** is
      **False**...

        * **ValueError** if the descriptor contents is malformed
        * **socket.timeout** if our request timed out
        * **urllib2.URLError** for most request failures

      Note that the urllib2 module may fail with other exception types, in
      which case we'll pass it along.
    """

    return list(self._run(suppress))

  def _run(self, suppress):
    with self._downloader_thread_lock:
      self.start()
      self._downloader_thread.join()

      if self.error:
        if suppress:
          return

        raise self.error
      else:
        if self.content is None:
          if suppress:
            return

          raise ValueError('BUG: _download_descriptors() finished without either results or an error')

        try:
          results = stem.descriptor.parse_file(
            io.BytesIO(self.content),
            self.descriptor_type,
            validate = self.validate,
            document_handler = self.document_handler,
            **self.kwargs
          )

          for desc in results:
            yield desc
        except ValueError as exc:
          self.error = exc  # encountered a parsing error

          if suppress:
            return

          raise self.error

  def __iter__(self):
    for desc in self._run(True):
      yield desc

  def _pick_url(self, use_authority = False):
    """
    Provides a url that can be queried. If we have multiple endpoints then one
    will be picked randomly.

    :param bool use_authority: ignores our endpoints and uses a directory
      authority instead

    :returns: **str** for the url being queried by this request
    """

    if use_authority or not self.endpoints:
      directories = get_authorities().values()

      picked = random.choice(directories)
      address, dirport = picked.address, picked.dir_port
    else:
      address, dirport = random.choice(self.endpoints)

    return 'http://%s:%i/%s' % (address, dirport, self.resource.lstrip('/'))

  def _download_descriptors(self, retries):
    try:
      use_authority = retries == 0 and self.fall_back_to_authority
      self.download_url = self._pick_url(use_authority)

      self.start_time = time.time()
      response = urllib.urlopen(self.download_url, timeout = self.timeout).read()

      if self.download_url.endswith('.z'):
        response = zlib.decompress(response)

      self.content = response.strip()

      self.runtime = time.time() - self.start_time
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
  Configurable class that issues :class:`~stem.descriptor.remote.Query`
  instances on your behalf.

  :param bool use_mirrors: downloads the present consensus and uses the directory
    mirrors to fetch future requests, this fails silently if the consensus
    cannot be downloaded
  :param default_args: default arguments for the
    :class:`~stem.descriptor.remote.Query` constructor
  """

  def __init__(self, use_mirrors = False, **default_args):
    self._default_args = default_args

    directories = list(get_authorities().values())
    self._endpoints = [(directory.address, directory.dir_port) for directory in directories]

    if use_mirrors:
      try:
        start_time = time.time()
        self.use_directory_mirrors()
        log.debug('Retrieved directory mirrors (took %0.2fs)' % (time.time() - start_time))
      except Exception as exc:
        log.debug('Unable to retrieve directory mirrors: %s' % exc)

  def use_directory_mirrors(self):
    """
    Downloads the present consensus and configures ourselves to use directory
    mirrors, in addition to authorities.

    :returns: :class:`~stem.descriptor.networkstatus.NetworkStatusDocumentV3`
      from which we got the directory mirrors

    :raises: **Exception** if unable to determine the directory mirrors
    """

    directories = get_authorities().values()
    new_endpoints = set([(directory.address, directory.dir_port) for directory in directories])

    consensus = list(self.get_consensus(document_handler = stem.descriptor.DocumentHandler.DOCUMENT).run())[0]

    for desc in consensus.routers.values():
      if Flag.V2DIR in desc.flags:
        new_endpoints.add((desc.address, desc.dir_port))

    # we need our endpoints to be a list rather than set for random.choice()

    self._endpoints = list(new_endpoints)

    return consensus

  def get_server_descriptors(self, fingerprints = None, **query_args):
    """
    Provides the server descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors in the present
    consensus.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/server/all.z'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i descriptors at a time by their fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/server/fp/%s.z' % '+'.join(fingerprints)

    return self.query(resource, **query_args)

  def get_extrainfo_descriptors(self, fingerprints = None, **query_args):
    """
    Provides the extrainfo descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors in the present
    consensus.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the extrainfo descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/extra/all.z'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i descriptors at a time by their fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/extra/fp/%s.z' % '+'.join(fingerprints)

    return self.query(resource, **query_args)

  # TODO: drop in python 2.x

  def get_microdescriptors(self, hashes, **query_args):
    """
    Provides the microdescriptors with the given hashes. To get these see the
    'microdescriptor_hashes' attribute of
    :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`. Note
    that these are only provided via a microdescriptor consensus (such as
    'cached-microdesc-consensus' in your data directory).

    .. deprecated:: 1.5.0
       This function has never worked, as it was never implemented in tor
       (:trac:`9271`).

    :param str,list hashes: microdescriptor hash or list of hashes to be
      retrieved
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the microdescriptors

    :raises: **ValueError** if we request more than 92 microdescriptors by their
      hashes (this is due to a limit on the url length by squid proxies).
    """

    if isinstance(hashes, str):
      hashes = [hashes]

    if len(hashes) > MAX_MICRODESCRIPTOR_HASHES:
      raise ValueError('Unable to request more than %i microdescriptors at a time by their hashes' % MAX_MICRODESCRIPTOR_HASHES)

    return self.query('/tor/micro/d/%s.z' % '-'.join(hashes), **query_args)

  def get_consensus(self, authority_v3ident = None, microdescriptor = False, **query_args):
    """
    Provides the present router status entries.

    .. versionchanged:: 1.5.0
       Added the microdescriptor argument.

    :param str authority_v3ident: fingerprint of the authority key for which
      to get the consensus, see `'v3ident' in tor's config.c
      <https://gitweb.torproject.org/tor.git/tree/src/or/config.c#n819>`_
      for the values.
    :param bool microdescriptor: provides the microdescriptor consensus if
      **True**, standard consensus otherwise
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the router status
      entries
    """

    if microdescriptor:
      resource = '/tor/status-vote/current/consensus-microdesc'
    else:
      resource = '/tor/status-vote/current/consensus'

    if authority_v3ident:
      resource += '/%s' % authority_v3ident

    return self.query(resource + '.z', **query_args)

  def get_vote(self, authority, **query_args):
    """
    Provides the present vote for a given directory authority.

    :param stem.descriptor.remote.DirectoryAuthority authority: authority for which to retrieve a vote for
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the router status
      entries
    """

    resource = '/tor/status-vote/current/authority'

    if 'endpoint' not in query_args:
      query_args['endpoints'] = [(authority.address, authority.dir_port)]

    return self.query(resource + '.z', **query_args)

  def get_key_certificates(self, authority_v3idents = None, **query_args):
    """
    Provides the key certificates for authorities with the given fingerprints.
    If no fingerprints are provided then this returns all present key
    certificates.

    :param str authority_v3idents: fingerprint or list of fingerprints of the
      authority keys, see `'v3ident' in tor's config.c
      <https://gitweb.torproject.org/tor.git/tree/src/or/config.c#n819>`_
      for the values.
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the key certificates

    :raises: **ValueError** if we request more than 96 key certificates by
      their identity fingerprints (this is due to a limit on the url length by
      squid proxies).
    """

    resource = '/tor/keys/all.z'

    if isinstance(authority_v3idents, str):
      authority_v3idents = [authority_v3idents]

    if authority_v3idents:
      if len(authority_v3idents) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i key certificates at a time by their identity fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/keys/fp/%s.z' % '+'.join(authority_v3idents)

    return self.query(resource, **query_args)

  def query(self, resource, **query_args):
    """
    Issues a request for the given resource.

    :param str resource: resource being fetched, such as '/tor/server/all.z'
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the descriptors

    :raises: **ValueError** if resource is clearly invalid or the descriptor
      type can't be determined when 'descriptor_type' is **None**
    """

    args = dict(self._default_args)
    args.update(query_args)

    if 'endpoints' not in args:
      args['endpoints'] = self._endpoints

    if 'fall_back_to_authority' not in args:
      args['fall_back_to_authority'] = True

    return Query(
      resource,
      **args
    )


class Directory(object):
  """
  Relay we can contact for directory information

  .. versionadded:: 1.5.0

  :var str address: IPv4 address of the directory
  :var int or_port: port on which the relay services relay traffic
  :var int dir_port: port on which directory information is available
  :var str fingerprint: relay fingerprint
  """

  def __init__(self, address, or_port, dir_port, fingerprint):
    self.address = address
    self.or_port = or_port
    self.dir_port = dir_port
    self.fingerprint = fingerprint

  def __hash__(self):
    return _hash_attr(self, 'address', 'or_port', 'dir_port', 'fingerprint')

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, Directory) else False

  def __ne__(self, other):
    return not self == other


class DirectoryAuthority(Directory):
  """
  Tor directory authority, a special type of relay `hardcoded into tor
  <https://gitweb.torproject.org/tor.git/tree/src/or/config.c#n819>`_
  that enumerates the other relays within the network.

  At a very high level tor works as follows...

  1. A volunteer starts up a new tor relay, during which it sends a `server
     descriptor <server_descriptor.html>`_ to each of the directory
     authorities.

  2. Each hour the directory authorities make a `vote <networkstatus.html>`_
     that says who they think the active relays are in the network and some
     attributes about them.

  3. The directory authorities send each other their votes, and compile that
     into the `consensus <networkstatus.html>`_. This document is very similar
     to the votes, the only difference being that the majority of the
     authorities agree upon and sign this document. The idividual relay entries
     in the vote or consensus is called `router status entries
     <router_status_entry.html>`_.

  4. Tor clients (people using the service) download the consensus from one of
     the authorities or a mirror to determine the active relays within the
     network. They in turn use this to construct their circuits and use the
     network.

  .. versionchanged:: 1.3.0
     Added the is_bandwidth_authority attribute.

  :var str nickname: nickname of the authority
  :var str v3ident: identity key fingerprint used to sign votes and consensus
  :var bool is_bandwidth_authority: **True** if this is a bandwidth authority,
    **False** otherwise
  """

  def __init__(self, address = None, or_port = None, dir_port = None, fingerprint = None, nickname = None, v3ident = None, is_bandwidth_authority = False):
    super(DirectoryAuthority, self).__init__(address, or_port, dir_port, fingerprint)
    self.nickname = nickname
    self.v3ident = v3ident
    self.is_bandwidth_authority = is_bandwidth_authority

  def __hash__(self):
    return _hash_attr(self, 'nickname', 'v3ident', 'is_bandwidth_authority', parent = Directory)

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, DirectoryAuthority) else False

  def __ne__(self, other):
    return not self == other


DIRECTORY_AUTHORITIES = {
  'moria1': DirectoryAuthority(
    nickname = 'moria1',
    address = '128.31.0.39',
    or_port = 9101,
    dir_port = 9131,
    is_bandwidth_authority = True,
    fingerprint = '9695DFC35FFEB861329B9F1AB04C46397020CE31',
    v3ident = 'D586D18309DED4CD6D57C18FDB97EFA96D330566',
  ),
  'tor26': DirectoryAuthority(
    nickname = 'tor26',
    address = '86.59.21.38',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = False,
    fingerprint = '847B1F850344D7876491A54892F904934E4EB85D',
    v3ident = '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
  ),
  'dizum': DirectoryAuthority(
    nickname = 'dizum',
    address = '194.109.206.212',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = False,
    fingerprint = '7EA6EAD6FD83083C538F44038BBFA077587DD755',
    v3ident = 'E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58',
  ),
  'gabelmoo': DirectoryAuthority(
    nickname = 'gabelmoo',
    address = '131.188.40.189',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = True,
    fingerprint = 'F2044413DAC2E02E3D6BCF4735A19BCA1DE97281',
    v3ident = 'ED03BB616EB2F60BEC80151114BB25CEF515B226',
  ),
  'dannenberg': DirectoryAuthority(
    nickname = 'dannenberg',
    address = '193.23.244.244',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = False,
    fingerprint = '7BE683E65D48141321C5ED92F075C55364AC7123',
    v3ident = '0232AF901C31A04EE9848595AF9BB7620D4C5B2E',
  ),
  'maatuska': DirectoryAuthority(
    nickname = 'maatuska',
    address = '171.25.193.9',
    or_port = 80,
    dir_port = 443,
    is_bandwidth_authority = True,
    fingerprint = 'BD6A829255CB08E66FBE7D3748363586E46B3810',
    v3ident = '49015F787433103580E3B66A1707A00E60F2D15B',
  ),
  'Faravahar': DirectoryAuthority(
    nickname = 'Faravahar',
    address = '154.35.175.225',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = True,
    fingerprint = 'CF6D0AAFB385BE71B8E111FC5CFF4B47923733BC',
    v3ident = 'EFCBE720AB3A82B99F9E953CD5BF50F7EEFC7B97',
  ),
  'longclaw': DirectoryAuthority(
    nickname = 'longclaw',
    address = '199.254.238.52',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = True,
    fingerprint = '74A910646BCEEFBCD2E874FC1DC997430F968145',
    v3ident = '23D15D965BC35114467363C165C4F724B64B4F66',
  ),
  'Bifroest': DirectoryAuthority(
    nickname = 'Bifroest',
    address = '37.218.247.217',
    or_port = 443,
    dir_port = 80,
    is_bandwidth_authority = False,
    fingerprint = '1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1',
    v3ident = None,  # does not vote in the consensus
  ),
}


def get_authorities():
  """
  Provides the Tor directory authority information as of **Tor on 11/21/14**.
  The directory information hardcoded into Tor and occasionally changes, so the
  information this provides might not necessarily match your version of tor.

  :returns: **dict** of **str** nicknames to :class:`~stem.descriptor.remote.DirectoryAuthority` instances
  """

  return dict(DIRECTORY_AUTHORITIES)


class FallbackDirectory(Directory):
  """
  Particularly stable relays tor can instead of authorities when
  bootstrapping. These relays are `hardcoded in tor
  <https://gitweb.torproject.org/tor.git/tree/src/or/fallback_dirs.inc>`_.

  For example, the following checks the performance of tor's fallback directories...

  ::

    import time
    from stem.descriptor.remote import DescriptorDownloader, FallbackDirectory

    downloader = DescriptorDownloader()

    for fallback_directory in FallbackDirectory.from_cache().values():
      start = time.time()
      downloader.get_consensus(endpoints = [(fallback_directory.address, fallback_directory.dir_port)]).run()
      print('Downloading the consensus took %0.2f from %s' % (time.time() - start, fallback_directory.fingerprint))

  ::

    % python example.py
    Downloading the consensus took 5.07 from 0AD3FA884D18F89EEA2D89C019379E0E7FD94417
    Downloading the consensus took 3.59 from C871C91489886D5E2E94C13EA1A5FDC4B6DC5204
    Downloading the consensus took 4.16 from 74A910646BCEEFBCD2E874FC1DC997430F968145
    ...

  .. versionadded:: 1.5.0

  :var str orport_v6: **(address, port)** tuple for the directory's IPv6
    ORPort, or **None** if it doesn't have one
  """

  def __init__(self, address = None, or_port = None, dir_port = None, fingerprint = None, orport_v6 = None):
    super(FallbackDirectory, self).__init__(address, or_port, dir_port, fingerprint)
    self.orport_v6 = orport_v6

  @staticmethod
  def from_cache():
    """
    Provides fallback directory information cached with Stem. Unlike
    :func:`~stem.descriptor.remote.FallbackDirectory.from_remote` this doesn't
    have any system requirements, and is faster too. Only drawback is that
    these fallback directories are only as up to date as the Stem release we're
    using.

    :returns: **dict** of **str** fingerprints to their
      :class:`~stem.descriptor.remote.FallbackDirectory`
    """

    conf = stem.util.conf.Config()
    conf.load(CACHE_PATH)

    results = {}

    for fingerprint in set([key.split('.')[0] for key in conf.keys()]):
      if fingerprint in ('tor_commit', 'stem_commit'):
        continue

      attr = {}

      for attr_name in ('address', 'or_port', 'dir_port', 'orport6_address', 'orport6_port'):
        key = '%s.%s' % (fingerprint, attr_name)
        attr[attr_name] = conf.get(key)

        if not attr[attr_name] and not attr_name.startswith('orport6_'):
          raise IOError("'%s' is missing from %s" % (key, CACHE_PATH))

      if not connection.is_valid_ipv4_address(attr['address']):
        raise IOError("'%s.address' was an invalid IPv4 address (%s)" % (fingerprint, attr['address']))
      elif not connection.is_valid_port(attr['or_port']):
        raise IOError("'%s.or_port' was an invalid port (%s)" % (fingerprint, attr['or_port']))
      elif not connection.is_valid_port(attr['dir_port']):
        raise IOError("'%s.dir_port' was an invalid port (%s)" % (fingerprint, attr['dir_port']))
      elif attr['orport6_address'] and not connection.is_valid_ipv6_address(attr['orport6_address']):
        raise IOError("'%s.orport6_address' was an invalid IPv6 address (%s)" % (fingerprint, attr['orport6_address']))
      elif attr['orport6_port'] and not connection.is_valid_port(attr['orport6_port']):
        raise IOError("'%s.orport6_port' was an invalid port (%s)" % (fingerprint, attr['orport6_port']))

      if attr['orport6_address'] and attr['orport6_port']:
        orport_v6 = (attr['orport6_address'], int(attr['orport6_port']))
      else:
        orport_v6 = None

      results[fingerprint] = FallbackDirectory(
        address = attr['address'],
        or_port = int(attr['or_port']),
        dir_port = int(attr['dir_port']),
        fingerprint = fingerprint,
        orport_v6 = orport_v6,
      )

    return results

  @staticmethod
  def from_remote(timeout = 60):
    """
    Reads and parses tor's latest fallback directories `from
    gitweb.torproject.org
    <https://gitweb.torproject.org/tor.git/plain/src/or/fallback_dirs.inc>`_.
    Note that while convenient, this reliance on GitWeb means you should alway
    call with a fallback, such as...

    ::

      try:
        fallback_directories = stem.descriptor.remote.from_remote()
      except IOError:
        fallback_directories = stem.descriptor.remote.from_cache()

    :param int timeout: seconds to wait before timing out the request

    :returns: **dict** of **str** fingerprints to their
      :class:`~stem.descriptor.remote.FallbackDirectory`

    :raises: **IOError** if unable to retrieve the fallback directories
    """

    try:
      fallback_dir_page = str_tools._to_unicode(urllib.urlopen(GITWEB_FALLBACK_DIR_URL, timeout = timeout).read())
    except:
      exc = sys.exc_info()[1]
      raise IOError("Unable to download tor's fallback directories from %s: %s" % (GITWEB_FALLBACK_DIR_URL, exc))

    # Example of an entry...
    #
    #   "5.175.233.86:80 orport=443 id=5525D0429BFE5DC4F1B0E9DE47A4CFA169661E33"
    #   " ipv6=[2a03:b0c0:0:1010::a4:b001]:9001"
    #   " weight=43680",

    results, attr = {}, {}

    for line in fallback_dir_page.splitlines():
      if line.startswith('"'):
        addr_line_match = re.match('"([\d\.]+):(\d+) orport=(\d+) id=([\dA-F]{40}).*', line)
        ipv6_line_match = re.match('" ipv6=\[([\da-f:]+)\]:(\d+)"', line)

        if addr_line_match:
          address, dir_port, or_port, fingerprint = addr_line_match.groups()

          if not connection.is_valid_ipv4_address(address):
            raise IOError('%s has an invalid IPv4 address: %s' % (fingerprint, address))
          elif not connection.is_valid_port(or_port):
            raise IOError('%s has an invalid or_port: %s' % (fingerprint, or_port))
          elif not connection.is_valid_port(dir_port):
            raise IOError('%s has an invalid dir_port: %s' % (fingerprint, dir_port))
          elif not tor_tools.is_valid_fingerprint(fingerprint):
            raise IOError('%s has an invalid fingerprint: %s' % (fingerprint, fingerprint))

          attr = {
            'address': address,
            'or_port': int(or_port),
            'dir_port': int(dir_port),
            'fingerprint': fingerprint,
          }
        elif ipv6_line_match:
          address, port = ipv6_line_match.groups()

          if not connection.is_valid_ipv6_address(address):
            raise IOError('%s has an invalid IPv6 address: %s' % (fingerprint, address))
          elif not connection.is_valid_port(port):
            raise IOError('%s has an invalid ORPort for its IPv6 endpoint: %s' % (fingerprint, port))

          attr['orport_v6'] = (address, int(port))
        elif line.startswith('" weight=') and 'fingerprint' in attr:
          results[attr.get('fingerprint')] = FallbackDirectory(
            address = attr.get('address'),
            or_port = attr.get('or_port'),
            dir_port = attr.get('dir_port'),
            fingerprint = attr.get('fingerprint'),
            orport_v6 = attr.get('orport_v6'),
          )

          attr = {}

    return results

  def __hash__(self):
    return _hash_attr(self, 'orport_v6', parent = Directory)

  def __eq__(self, other):
    return hash(self) == hash(other) if isinstance(other, FallbackDirectory) else False

  def __ne__(self, other):
    return not self == other


def _fallback_directory_differences(previous_directories, new_directories):
  """
  Provides a description of how fallback directories differ.
  """

  lines = []

  added_fp = set(new_directories.keys()).difference(previous_directories.keys())
  removed_fp = set(previous_directories.keys()).difference(new_directories.keys())

  for fp in added_fp:
    directory = new_directories[fp]

    lines += [
      '* Added %s as a new fallback directory:' % directory.fingerprint,
      '  address: %s' % directory.address,
      '  or_port: %s' % directory.or_port,
      '  dir_port: %s' % directory.dir_port,
      '  orport_v6: %s' % directory.orport_v6 if directory.orport_v6 else '[none]',
      '',
    ]

  for fp in removed_fp:
    lines.append('* Removed %s as a fallback directory' % fp)

  for fp in new_directories:
    if fp in added_fp or fp in removed_fp:
      continue  # already discussed these

    previous_directory = previous_directories[fp]
    new_directory = new_directories[fp]

    if previous_directory != new_directory:
      for attr in ('address', 'or_port', 'dir_port', 'fingerprint', 'orport_v6'):
        old_attr = getattr(previous_directory, attr)
        new_attr = getattr(new_directory, attr)

        if old_attr != new_attr:
          lines.append('* Changed the %s of %s from %s to %s' % (attr, fp, old_attr, new_attr))

  return '\n'.join(lines)
