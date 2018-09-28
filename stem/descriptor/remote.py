# Copyright 2013-2018, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Module for remotely retrieving descriptors from directory authorities and
mirrors. This is the simplest method for getting current tor descriptor
information...

::

  import stem.descriptor.remote

  for desc in stem.descriptor.remote.get_server_descriptors():
    if desc.exit_policy.is_exiting_allowed():
      print('  %s (%s)' % (desc.nickname, desc.fingerprint))

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

  print('Exit Relays:')

  try:
    for desc in query.run():
      if desc.exit_policy.is_exiting_allowed():
        print('  %s (%s)' % (desc.nickname, desc.fingerprint))

    print
    print('Query took %0.2f seconds' % query.runtime)
  except Exception as exc:
    print('Unable to retrieve the server descriptors: %s' % exc)

::

  get_instance - Provides a singleton DescriptorDownloader used for...
    |- their_server_descriptor - provides the server descriptor of the relay we download from
    |- get_server_descriptors - provides present server descriptors
    |- get_extrainfo_descriptors - provides present extrainfo descriptors
    +- get_consensus - provides the present consensus or router status entries

  Query - Asynchronous request to download tor descriptors
    |- start - issues the query if it isn't already running
    +- run - blocks until the request is finished and provides the results

  DescriptorDownloader - Configurable class for issuing queries
    |- use_directory_mirrors - use directory mirrors to download future descriptors
    |- their_server_descriptor - provides the server descriptor of the relay we download from
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

.. data:: Compression (enum)

  Compression when downloading descriptors.

  .. versionadded:: 1.7.0

  =============== ===========
  Compression     Description
  =============== ===========
  **PLAINTEXT**   Uncompressed data.
  **GZIP**        `GZip compression <https://www.gnu.org/software/gzip/>`_.
  **ZSTD**        `Zstandard compression <https://www.zstd.net>`_, this requires the `zstandard module <https://pypi.python.org/pypi/zstandard>`_.
  **LZMA**        `LZMA compression <https://en.wikipedia.org/wiki/LZMA>`_, this requires the 'lzma module <https://docs.python.org/3/library/lzma.html>`_.
  =============== ===========
"""

import io
import random
import sys
import threading
import time
import zlib

import stem
import stem.client
import stem.descriptor
import stem.directory
import stem.prereq
import stem.util.enum

from stem.client.datatype import RelayCommand
from stem.util import log, str_tools

try:
  # account for urllib's change between python 2.x and 3.x
  import urllib.request as urllib
except ImportError:
  import urllib2 as urllib

Compression = stem.util.enum.Enum(
  ('PLAINTEXT', 'identity'),
  ('GZIP', 'gzip'),  # can also be 'deflate'
  ('ZSTD', 'x-zstd'),
  ('LZMA', 'x-tor-lzma'),
)

# Tor has a limited number of descriptors we can fetch explicitly by their
# fingerprint or hashes due to a limit on the url length by squid proxies.

MAX_FINGERPRINTS = 96
MAX_MICRODESCRIPTOR_HASHES = 90

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


def their_server_descriptor(**query_args):
  """
  Provides the server descriptor of the relay we're downloading from.

  .. versionadded:: 1.7.0

  :param query_args: additional arguments for the
    :class:`~stem.descriptor.remote.Query` constructor

  :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors
  """

  return get_instance().their_server_descriptor(**query_args)


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
      '/tor/server/all',
      block = True,
      timeout = 30,
    )

    print('Current relays:')

    if not query.error:
      for desc in query:
        print(desc.fingerprint)
    else:
      print('Unable to retrieve the server descriptors: %s' % query.error)

  ... while iterating fails silently...

  ::

    print('Current relays:')

    for desc in Query('/tor/server/all', 'server-descriptor 1.0'):
      print(desc.fingerprint)

  In either case exceptions are available via our 'error' attribute.

  Tor provides quite a few different descriptor resources via its directory
  protocol (see section 4.2 and later of the `dir-spec
  <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_).
  Commonly useful ones include...

  =============================================== ===========
  Resource                                        Description
  =============================================== ===========
  /tor/server/all                                 all present server descriptors
  /tor/server/fp/<fp1>+<fp2>+<fp3>                server descriptors with the given fingerprints
  /tor/extra/all                                  all present extrainfo descriptors
  /tor/extra/fp/<fp1>+<fp2>+<fp3>                 extrainfo descriptors with the given fingerprints
  /tor/micro/d/<hash1>-<hash2>                    microdescriptors with the given hashes
  /tor/status-vote/current/consensus              present consensus
  /tor/status-vote/current/consensus-microdesc    present microdescriptor consensus
  /tor/keys/all                                   key certificates for the authorities
  /tor/keys/fp/<v3ident1>+<v3ident2>              key certificates for specific authorities
  =============================================== ===========

  **ZSTD** compression requires `zstandard
  <https://pypi.python.org/pypi/zstandard>`_, and **LZMA** requires the `lzma
  module <https://docs.python.org/3/library/lzma.html>`_.

  For legacy reasons if our resource has a '.z' suffix then our **compression**
  argument is overwritten with Compression.GZIP.

  .. versionchanged:: 1.7.0
     Added support for downloading from ORPorts.

  .. versionchanged:: 1.7.0
     Added the compression argument.

  .. versionchanged:: 1.7.0
     Added the reply_headers attribute.

     The class this provides changed between Python versions. In python2
     this was called httplib.HTTPMessage, whereas in python3 the class was
     renamed to http.client.HTTPMessage.

  .. versionchanged:: 1.7.0
     Endpoints are now expected to be :class:`~stem.DirPort` or
     :class:`~stem.ORPort` instances. Usage of tuples for this
     argument is deprecated and will be removed in the future.

  .. versionchanged:: 1.7.0
     Avoid downloading from tor26. This directory authority throttles its
     DirPort to such an extent that requests either time out or take on the
     order of minutes.

  .. versionchanged:: 1.7.0
     Avoid downloading from Bifroest. This is the bridge authority so it
     doesn't vote in the consensus, and apparently times out frequently.

  :var str resource: resource being fetched, such as '/tor/server/all'
  :var str descriptor_type: type of descriptors being fetched (for options see
    :func:`~stem.descriptor.__init__.parse_file`), this is guessed from the
    resource if **None**

  :var list endpoints: :class:`~stem.DirPort` or :class:`~stem.ORPort` of the
    authority or mirror we're querying, this uses authorities if undefined
  :var list compression: list of :data:`stem.descriptor.remote.Compression`
    we're willing to accept, when none are mutually supported downloads fall
    back to Compression.PLAINTEXT
  :var int retries: number of times to attempt the request if downloading it
    fails
  :var bool fall_back_to_authority: when retrying request issues the last
    request to a directory authority if **True**

  :var str content: downloaded descriptor content
  :var Exception error: exception if a problem occured
  :var bool is_done: flag that indicates if our request has finished

  :var float start_time: unix timestamp when we first started running
  :var http.client.HTTPMessage reply_headers: headers provided in the response,
    **None** if we haven't yet made our request
  :var float runtime: time our query took, this is **None** if it's not yet
    finished

  :var bool validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :var stem.descriptor.__init__.DocumentHandler document_handler: method in
    which to parse a :class:`~stem.descriptor.networkstatus.NetworkStatusDocument`
  :var dict kwargs: additional arguments for the descriptor constructor

  Following are only applicable when downloading from a
  :class:`~stem.DirPort`...

  :var float timeout: duration before we'll time out our request
  :var str download_url: last url used to download the descriptor, this is
    unset until we've actually made a download attempt

  :param bool start: start making the request when constructed (default is **True**)
  :param bool block: only return after the request has been completed, this is
    the same as running **query.run(True)** (default is **False**)
  """

  def __init__(self, resource, descriptor_type = None, endpoints = None, compression = None, retries = 2, fall_back_to_authority = False, timeout = None, start = True, block = False, validate = False, document_handler = stem.descriptor.DocumentHandler.ENTRIES, **kwargs):
    if not resource.startswith('/'):
      raise ValueError("Resources should start with a '/': %s" % resource)

    if resource.endswith('.z'):
      compression = [Compression.GZIP]
      resource = resource[:-2]
    elif compression is None:
      compression = [Compression.PLAINTEXT]
    else:
      if isinstance(compression, str):
        compression = [compression]  # caller provided only a single option

      if Compression.ZSTD in compression and not stem.prereq.is_zstd_available():
        compression.remove(Compression.ZSTD)

      if Compression.LZMA in compression and not stem.prereq.is_lzma_available():
        compression.remove(Compression.LZMA)

      if not compression:
        compression = [Compression.PLAINTEXT]

    if descriptor_type:
      self.descriptor_type = descriptor_type
    else:
      self.descriptor_type = _guess_descriptor_type(resource)

    self.endpoints = []

    if endpoints:
      for endpoint in endpoints:
        if isinstance(endpoint, tuple) and len(endpoint) == 2:
          self.endpoints.append(stem.DirPort(endpoint[0], endpoint[1]))  # TODO: remove this in stem 2.0
        elif isinstance(endpoint, (stem.ORPort, stem.DirPort)):
          self.endpoints.append(endpoint)
        else:
          raise ValueError("Endpoints must be an stem.ORPort, stem.DirPort, or two value tuple. '%s' is a %s." % (endpoint, type(endpoint).__name__))

    self.resource = resource
    self.compression = compression
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
    self.reply_headers = None
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
          name = 'Descriptor query',
          target = self._download_descriptors,
          args = (self.retries, self.timeout)
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

  def _pick_endpoint(self, use_authority = False):
    """
    Provides an endpoint to query. If we have multiple endpoints then one
    is picked at random.

    :param bool use_authority: ignores our endpoints and uses a directory
      authority instead

    :returns: **str** for the url being queried by this request
    """

    if use_authority or not self.endpoints:
      picked = random.choice([auth for auth in stem.directory.Authority.from_cache().values() if auth.nickname not in ('tor26', 'Bifroest')])
      return stem.DirPort(picked.address, picked.dir_port)
    else:
      return random.choice(self.endpoints)

  def _download_descriptors(self, retries, timeout):
    try:
      self.start_time = time.time()
      endpoint = self._pick_endpoint(use_authority = retries == 0 and self.fall_back_to_authority)

      if isinstance(endpoint, stem.ORPort):
        self.content, self.reply_headers = _download_from_orport(endpoint, self.compression, self.resource)
      elif isinstance(endpoint, stem.DirPort):
        self.download_url = 'http://%s:%i/%s' % (endpoint.address, endpoint.port, self.resource.lstrip('/'))
        self.content, self.reply_headers = _download_from_dirport(self.download_url, self.compression, timeout)
      else:
        raise ValueError("BUG: endpoints can only be ORPorts or DirPorts, '%s' was a %s" % (endpoint, type(endpoint).__name__))

      self.runtime = time.time() - self.start_time
      log.trace("Descriptors retrieved from '%s' in %0.2fs" % (self.download_url, self.runtime))
    except:
      exc = sys.exc_info()[1]

      if timeout is not None:
        timeout -= time.time() - self.start_time

      if retries > 0 and (timeout is None or timeout > 0):
        log.debug("Unable to download descriptors from '%s' (%i retries remaining): %s" % (self.download_url, retries, exc))
        return self._download_descriptors(retries - 1, timeout)
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

    directories = list(stem.directory.Authority.from_cache().values())
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

    directories = stem.directory.Authority.from_cache().values()
    new_endpoints = set([(directory.address, directory.dir_port) for directory in directories])

    consensus = list(self.get_consensus(document_handler = stem.descriptor.DocumentHandler.DOCUMENT).run())[0]

    for desc in consensus.routers.values():
      if stem.Flag.V2DIR in desc.flags:
        new_endpoints.add((desc.address, desc.dir_port))

    # we need our endpoints to be a list rather than set for random.choice()

    self._endpoints = list(new_endpoints)

    return consensus

  def their_server_descriptor(self, **query_args):
    """
    Provides the server descriptor of the relay we're downloading from.

    .. versionadded:: 1.7.0

    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors
    """

    return self.query('/tor/server/authority', **query_args)

  def get_server_descriptors(self, fingerprints = None, **query_args):
    """
    Provides the server descriptors with the given fingerprints. If no
    fingerprints are provided then this returns all descriptors known
    by the relay.

    :param str,list fingerprints: fingerprint or list of fingerprints to be
      retrieved, gets all descriptors if **None**
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the server descriptors

    :raises: **ValueError** if we request more than 96 descriptors by their
      fingerprints (this is due to a limit on the url length by squid proxies).
    """

    resource = '/tor/server/all'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i descriptors at a time by their fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/server/fp/%s' % '+'.join(fingerprints)

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

    resource = '/tor/extra/all'

    if isinstance(fingerprints, str):
      fingerprints = [fingerprints]

    if fingerprints:
      if len(fingerprints) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i descriptors at a time by their fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/extra/fp/%s' % '+'.join(fingerprints)

    return self.query(resource, **query_args)

  # TODO: drop in stem 2.x

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

    return self.query('/tor/micro/d/%s' % '-'.join(hashes), **query_args)

  def get_consensus(self, authority_v3ident = None, microdescriptor = False, **query_args):
    """
    Provides the present router status entries.

    .. versionchanged:: 1.5.0
       Added the microdescriptor argument.

    :param str authority_v3ident: fingerprint of the authority key for which
      to get the consensus, see `'v3ident' in tor's config.c
      <https://gitweb.torproject.org/tor.git/tree/src/or/config.c>`_
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

    consensus_query = self.query(resource, **query_args)

    # if we're performing validation then check that it's signed by the
    # authority key certificates

    if consensus_query.validate and consensus_query.document_handler == stem.descriptor.DocumentHandler.DOCUMENT and stem.prereq.is_crypto_available():
      consensus = list(consensus_query.run())[0]
      key_certs = self.get_key_certificates(**query_args).run()
      consensus.validate_signatures(key_certs)

    return consensus_query

  def get_vote(self, authority, **query_args):
    """
    Provides the present vote for a given directory authority.

    :param stem.directory.Authority authority: authority for which to retrieve a vote for
    :param query_args: additional arguments for the
      :class:`~stem.descriptor.remote.Query` constructor

    :returns: :class:`~stem.descriptor.remote.Query` for the router status
      entries
    """

    resource = '/tor/status-vote/current/authority'

    if 'endpoint' not in query_args:
      query_args['endpoints'] = [(authority.address, authority.dir_port)]

    return self.query(resource, **query_args)

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

    resource = '/tor/keys/all'

    if isinstance(authority_v3idents, str):
      authority_v3idents = [authority_v3idents]

    if authority_v3idents:
      if len(authority_v3idents) > MAX_FINGERPRINTS:
        raise ValueError('Unable to request more than %i key certificates at a time by their identity fingerprints' % MAX_FINGERPRINTS)

      resource = '/tor/keys/fp/%s' % '+'.join(authority_v3idents)

    return self.query(resource, **query_args)

  def query(self, resource, **query_args):
    """
    Issues a request for the given resource.

    .. versionchanged:: 1.7.0
       The **fall_back_to_authority** default when using this method is now
       **False**, like the :class:`~stem.descriptor.Query` class.

    :param str resource: resource being fetched, such as '/tor/server/all'
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

    return Query(resource, **args)


def _download_from_orport(endpoint, compression, resource):
  """
  Downloads descriptors from the given orport. Payload is just like an http
  response (headers and all)...

  ::

    HTTP/1.0 200 OK
    Date: Mon, 23 Apr 2018 18:43:47 GMT
    Content-Type: text/plain
    X-Your-Address-Is: 216.161.254.25
    Content-Encoding: identity
    Expires: Wed, 25 Apr 2018 18:43:47 GMT

    router dannenberg 193.23.244.244 443 0 80
    identity-ed25519
    ... rest of the descriptor content...

  :param stem.ORPort endpoint: endpoint to download from
  :param list compression: compression methods for the request
  :param str resource: descriptor resource to download

  :returns: two value tuple of the form (data, reply_headers)

  :raises:
    * :class:`stem.ProtocolError` if not a valid descriptor response
    * :class:`stem.SocketError` if unable to establish a connection
  """

  link_protocols = endpoint.link_protocols if endpoint.link_protocols else [3]

  with stem.client.Relay.connect(endpoint.address, endpoint.port, link_protocols) as relay:
    with relay.create_circuit() as circ:
      request = '\r\n'.join((
        'GET %s HTTP/1.0' % resource,
        'Accept-Encoding: %s' % ', '.join(compression),
        'User-Agent: %s' % stem.USER_AGENT,
      )) + '\r\n\r\n'

      circ.send(RelayCommand.BEGIN_DIR, stream_id = 1)
      response = b''.join([cell.data for cell in circ.send(RelayCommand.DATA, request, stream_id = 1)])
      first_line, data = response.split(b'\r\n', 1)
      header_data, body_data = data.split(b'\r\n\r\n', 1)

      if not first_line.startswith(b'HTTP/1.0 2'):
        raise stem.ProtocolError("Response should begin with HTTP success, but was '%s'" % str_tools._to_unicode(first_line))

      headers = {}

      for line in str_tools._to_unicode(header_data).splitlines():
        if ': ' not in line:
          raise stem.ProtocolError("'%s' is not a HTTP header:\n\n%s" % line)

        key, value = line.split(': ', 1)
        headers[key] = value

      return _decompress(body_data, headers.get('Content-Encoding')), headers


def _download_from_dirport(url, compression, timeout):
  """
  Downloads descriptors from the given url.

  :param str url: dirport url from which to download from
  :param list compression: compression methods for the request
  :param float timeout: duration before we'll time out our request

  :returns: two value tuple of the form (data, reply_headers)

  :raises:
    * **socket.timeout** if our request timed out
    * **urllib2.URLError** for most request failures
  """

  response = urllib.urlopen(
    urllib.Request(
      url,
      headers = {
        'Accept-Encoding': ', '.join(compression),
        'User-Agent': stem.USER_AGENT,
      }
    ),
    timeout = timeout,
  )

  return _decompress(response.read(), response.headers.get('Content-Encoding')), response.headers


def _decompress(data, encoding):
  """
  Decompresses descriptor data.

  Tor doesn't include compression headers. As such when using gzip we
  need to include '32' for automatic header detection...

    https://stackoverflow.com/questions/3122145/zlib-error-error-3-while-decompressing-incorrect-header-check/22310760#22310760

  ... and with zstd we need to use the streaming API.

  :param bytes data: data we received
  :param str encoding: 'Content-Encoding' header of the response

  :raises:
    * **ValueError** if encoding is unrecognized
    * **ImportError** if missing the decompression module
  """

  if encoding == Compression.PLAINTEXT:
    return data.strip()
  elif encoding in (Compression.GZIP, 'deflate'):
    return zlib.decompress(data, zlib.MAX_WBITS | 32).strip()
  elif encoding == Compression.ZSTD:
    if not stem.prereq.is_zstd_available():
      raise ImportError('Decompressing zstd data requires https://pypi.python.org/pypi/zstandard')

    import zstd
    output_buffer = io.BytesIO()

    with zstd.ZstdDecompressor().write_to(output_buffer) as decompressor:
      decompressor.write(data)

    return output_buffer.getvalue().strip()
  elif encoding == Compression.LZMA:
    if not stem.prereq.is_lzma_available():
      raise ImportError('Decompressing lzma data requires https://docs.python.org/3/library/lzma.html')

    import lzma
    return lzma.decompress(data).strip()
  else:
    raise ValueError("'%s' isn't a recognized type of encoding" % encoding)


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


def get_authorities():
  """
  Provides cached Tor directory authority information. The directory
  information hardcoded into Tor and occasionally changes, so the information
  this provides might not necessarily match your version of tor.

  .. deprecated:: 1.7.0
     Use stem.directory.Authority.from_cache() instead.

  :returns: **dict** of **str** nicknames to :class:`~stem.directory.Authority` instances
  """

  return DirectoryAuthority.from_cache()


# TODO: drop aliases in stem 2.0

Directory = stem.directory.Directory
DirectoryAuthority = stem.directory.Authority
FallbackDirectory = stem.directory.Fallback
