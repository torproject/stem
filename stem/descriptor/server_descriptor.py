# Copyright 2012-2020, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for Tor server descriptors, which contains the infrequently changing
information about a Tor relay (contact information, exit policy, public keys,
etc). This information is provided from a few sources...

* The control port via 'GETINFO desc/\\*' queries.

* The 'cached-descriptors' file in Tor's data directory.

* Archived descriptors provided by `CollecTor <https://metrics.torproject.org/collector.html>`_.

* Directory authorities and mirrors via their DirPort.

**Module Overview:**

::

  ServerDescriptor - Tor server descriptor.
    |- RelayDescriptor - Server descriptor for a relay.
    |  +- make_router_status_entry - Creates a router status entry for this descriptor.
    |
    |- BridgeDescriptor - Scrubbed server descriptor for a bridge.
    |  |- is_scrubbed - checks if our content has been properly scrubbed
    |  +- get_scrubbing_issues - description of issues with our scrubbing
    |
    +- digest - calculates the upper-case hex digest value for our content

.. data:: BridgeDistribution (enum)

  Preferred method of distributing this relay if a bridge.

  .. versionadded:: 1.6.0

  ===================== ===========
  BridgeDistribution    Description
  ===================== ===========
  **ANY**               No proference, BridgeDB will pick how the bridge is distributed.
  **HTTPS**             Provided via the `web interface <https://bridges.torproject.org>`_.
  **EMAIL**             Provided in response to emails to bridges@torproject.org.
  **MOAT**              Provided in interactive menus within Tor Browser.
  **HYPHAE**            Provided via a cryptographic invitation-based system.
  ===================== ===========
"""

import base64
import binascii
import functools
import hashlib
import re

import stem.descriptor.extrainfo_descriptor
import stem.exit_policy
import stem.util.connection
import stem.util.enum
import stem.util.str_tools
import stem.util.tor_tools
import stem.version

from stem.descriptor.certificate import Ed25519Certificate
from stem.descriptor.router_status_entry import RouterStatusEntryV3
from typing import Any, BinaryIO, Iterator, Optional, Mapping, Sequence, Tuple, Type, Union

from stem.descriptor import (
  ENTRY_TYPE,
  PGP_BLOCK_END,
  Descriptor,
  DigestHash,
  DigestEncoding,
  create_signing_key,
  _descriptor_content,
  _descriptor_components_with_extra,
  _read_until_keywords,
  _bytes_for_block,
  _value,
  _values,
  _parse_simple_line,
  _parse_int_line,
  _parse_if_present,
  _parse_bytes_line,
  _parse_timestamp_line,
  _parse_forty_character_hex,
  _parse_protocol_line,
  _parse_key_block,
  _append_router_signature,
  _random_nickname,
  _random_ipv4_address,
  _random_date,
  _random_crypto_blob,
)

# relay descriptors must have exactly one of the following
REQUIRED_FIELDS = (
  'router',
  'bandwidth',
  'published',
  'onion-key',
  'signing-key',
  'router-signature',
)

# optional entries that can appear at most once
SINGLE_FIELDS = (
  'identity-ed25519',
  'master-key-ed25519',
  'platform',
  'fingerprint',
  'hibernating',
  'uptime',
  'contact',
  'read-history',
  'write-history',
  'eventdns',
  'bridge-distribution-request',
  'family',
  'caches-extra-info',
  'extra-info-digest',
  'hidden-service-dir',
  'protocols',
  'allow-single-hop-exits',
  'tunnelled-dir-server',
  'proto',
  'onion-key-crosscert',
  'ntor-onion-key',
  'ntor-onion-key-crosscert',
  'router-sig-ed25519',
)

BridgeDistribution = stem.util.enum.Enum(
  ('ANY', 'any'),
  ('HTTPS', 'https'),
  ('EMAIL', 'email'),
  ('MOAT', 'moat'),
  ('HYPHAE', 'hyphae'),
)

DEFAULT_IPV6_EXIT_POLICY = stem.exit_policy.MicroExitPolicy('reject 1-65535')
REJECT_ALL_POLICY = stem.exit_policy.ExitPolicy('reject *:*')
DEFAULT_BRIDGE_DISTRIBUTION = 'any'


def _truncated_b64encode(content: bytes) -> str:
  return stem.util.str_tools._to_unicode(base64.b64encode(content).rstrip(b'='))


def _parse_file(descriptor_file: BinaryIO, is_bridge: bool = False, validate: bool = False, **kwargs: Any) -> Iterator['stem.descriptor.server_descriptor.ServerDescriptor']:
  """
  Iterates over the server descriptors in a file.

  :param descriptor_file: file with descriptor content
  :param is_bridge: parses the file as being a bridge descriptor
  :param validate: checks the validity of the descriptor's content if
    **True**, skips these checks otherwise
  :param kwargs: additional arguments for the descriptor constructor

  :returns: iterator for ServerDescriptor instances in the file

  :raises:
    * **ValueError** if the contents is malformed and validate is True
    * **OSError** if the file can't be read
  """

  # Handler for relay descriptors
  #
  # Cached descriptors consist of annotations followed by the descriptor
  # itself. For instance...
  #
  #   @downloaded-at 2012-03-14 16:31:05
  #   @source "145.53.65.130"
  #   router caerSidi 71.35.143.157 9001 0 0
  #   platform Tor 0.2.1.30 on Linux x86_64
  #   <rest of the descriptor content>
  #   router-signature
  #   -----BEGIN SIGNATURE-----
  #   <signature for the above descriptor>
  #   -----END SIGNATURE-----
  #
  # Metrics descriptor files are the same, but lack any annotations. The
  # following simply does the following...
  #
  #   - parse as annotations until we get to 'router'
  #   - parse as descriptor content until we get to 'router-signature' followed
  #     by the end of the signature block
  #   - construct a descriptor and provide it back to the caller
  #
  # Any annotations after the last server descriptor is ignored (never provided
  # to the caller).

  while True:
    # skip annotations

    while True:
      pos = descriptor_file.tell()

      if not descriptor_file.readline().startswith(b'@'):
        descriptor_file.seek(pos)
        break

    if not is_bridge:
      descriptor_content = _read_until_keywords('router-signature', descriptor_file)

      # we've reached the 'router-signature', now include the pgp style block

      block_end_prefix = PGP_BLOCK_END.split(' ', 1)[0]
      descriptor_content += _read_until_keywords(block_end_prefix, descriptor_file, True)
    else:
      descriptor_content = _read_until_keywords('router-digest', descriptor_file, True)

    if descriptor_content:
      if descriptor_content[0].startswith(b'@type'):
        descriptor_content = descriptor_content[1:]

      descriptor_text = bytes.join(b'', descriptor_content)

      if is_bridge:
        if kwargs:
          raise ValueError('BUG: keyword arguments unused by bridge descriptors')

        yield BridgeDescriptor(descriptor_text, validate)
      else:
        yield RelayDescriptor(descriptor_text, validate, **kwargs)
    else:
      break  # done parsing descriptors


def _parse_router_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  # "router" nickname address ORPort SocksPort DirPort

  value = _value('router', entries)
  router_comp = value.split()

  if len(router_comp) < 5:
    raise ValueError('Router line must have five values: router %s' % value)
  elif not stem.util.tor_tools.is_valid_nickname(router_comp[0]):
    raise ValueError("Router line entry isn't a valid nickname: %s" % router_comp[0])
  elif not stem.util.connection.is_valid_ipv4_address(router_comp[1]):
    raise ValueError("Router line entry isn't a valid IPv4 address: %s" % router_comp[1])
  elif not stem.util.connection.is_valid_port(router_comp[2], allow_zero = True):
    raise ValueError("Router line's ORPort is invalid: %s" % router_comp[2])
  elif not stem.util.connection.is_valid_port(router_comp[3], allow_zero = True):
    raise ValueError("Router line's SocksPort is invalid: %s" % router_comp[3])
  elif not stem.util.connection.is_valid_port(router_comp[4], allow_zero = True):
    raise ValueError("Router line's DirPort is invalid: %s" % router_comp[4])

  descriptor.nickname = router_comp[0]
  descriptor.address = router_comp[1]
  descriptor.or_port = int(router_comp[2])
  descriptor.socks_port = None if router_comp[3] == '0' else int(router_comp[3])
  descriptor.dir_port = None if router_comp[4] == '0' else int(router_comp[4])


def _parse_bandwidth_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  # "bandwidth" bandwidth-avg bandwidth-burst bandwidth-observed

  value = _value('bandwidth', entries)
  bandwidth_comp = value.split()

  if len(bandwidth_comp) < 3:
    raise ValueError('Bandwidth line must have three values: bandwidth %s' % value)
  elif not bandwidth_comp[0].isdigit():
    raise ValueError("Bandwidth line's average rate isn't numeric: %s" % bandwidth_comp[0])
  elif not bandwidth_comp[1].isdigit():
    raise ValueError("Bandwidth line's burst rate isn't numeric: %s" % bandwidth_comp[1])
  elif not bandwidth_comp[2].isdigit():
    raise ValueError("Bandwidth line's observed rate isn't numeric: %s" % bandwidth_comp[2])

  descriptor.average_bandwidth = int(bandwidth_comp[0])
  descriptor.burst_bandwidth = int(bandwidth_comp[1])
  descriptor.observed_bandwidth = int(bandwidth_comp[2])


def _parse_platform_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  # "platform" string

  _parse_bytes_line('platform', 'platform')(descriptor, entries)

  # The platform attribute was set earlier. This line can contain any
  # arbitrary data, but tor seems to report its version followed by the
  # os like the following...
  #
  #   platform Tor 0.2.2.35 (git-73ff13ab3cc9570d) on Linux x86_64
  #
  # There's no guarantee that we'll be able to pick these out the
  # version, but might as well try to save our caller the effort.

  value = _value('platform', entries)
  platform_match = re.match('^(?:node-)?Tor (\\S*).* on (.*)$', value)

  if platform_match:
    version_str, descriptor.operating_system = platform_match.groups()

    try:
      descriptor.tor_version = stem.version._get_version(version_str)
    except ValueError:
      pass


def _parse_fingerprint_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  # This is forty hex digits split into space separated groups of four.
  # Checking that we match this pattern.

  value = _value('fingerprint', entries)
  fingerprint = value.replace(' ', '')

  for grouping in value.split(' '):
    if len(grouping) != 4:
      raise ValueError('Fingerprint line should have groupings of four hex digits: %s' % value)

  if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
    raise ValueError('Tor relay fingerprints consist of forty hex digits: %s' % value)

  descriptor.fingerprint = fingerprint


def _parse_extrainfo_digest_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  value = _value('extra-info-digest', entries)
  digest_comp = value.split(' ')

  if not stem.util.tor_tools.is_hex_digits(digest_comp[0], 40):
    raise ValueError('extra-info-digest should be 40 hex characters: %s' % digest_comp[0])

  descriptor.extra_info_digest = digest_comp[0]
  descriptor.extra_info_sha256_digest = digest_comp[1] if len(digest_comp) >= 2 else None


def _parse_hibernating_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  # "hibernating" 0|1 (in practice only set if one)

  value = _value('hibernating', entries)

  if value not in ('0', '1'):
    raise ValueError('Hibernating line had an invalid value, must be zero or one: %s' % value)

  descriptor.hibernating = value == '1'


def _parse_protocols_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  value = _value('protocols', entries)
  protocols_match = re.match('^Link (.*) Circuit (.*)$', value)

  if not protocols_match:
    raise ValueError('Protocols line did not match the expected pattern: protocols %s' % value)

  link_versions, circuit_versions = protocols_match.groups()
  descriptor.link_protocols = link_versions.split(' ')
  descriptor.circuit_protocols = circuit_versions.split(' ')


def _parse_or_address_line(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  all_values = _values('or-address', entries)
  or_addresses = []

  for entry in all_values:
    line = 'or-address %s' % entry

    if ':' not in entry:
      raise ValueError('or-address line missing a colon: %s' % line)

    address, port = entry.rsplit(':', 1)

    if not stem.util.connection.is_valid_ipv4_address(address) and not stem.util.connection.is_valid_ipv6_address(address, allow_brackets = True):
      raise ValueError('or-address line has a malformed address: %s' % line)

    if not stem.util.connection.is_valid_port(port):
      raise ValueError('or-address line has a malformed port: %s' % line)

    or_addresses.append((address.lstrip('[').rstrip(']'), int(port), stem.util.connection.is_valid_ipv6_address(address, allow_brackets = True)))

  descriptor.or_addresses = or_addresses


def _parse_history_line(keyword: str, history_end_attribute: str, history_interval_attribute: str, history_values_attribute: str, descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  value = _value(keyword, entries)
  timestamp, interval, remainder = stem.descriptor.extrainfo_descriptor._parse_timestamp_and_interval(keyword, value)

  try:
    if remainder:
      history_values = [int(entry) for entry in remainder.split(',')]
    else:
      history_values = []
  except ValueError:
    raise ValueError('%s line has non-numeric values: %s %s' % (keyword, keyword, value))

  setattr(descriptor, history_end_attribute, timestamp)
  setattr(descriptor, history_interval_attribute, interval)
  setattr(descriptor, history_values_attribute, history_values)


def _parse_exit_policy(descriptor: 'stem.descriptor.Descriptor', entries: ENTRY_TYPE) -> None:
  if hasattr(descriptor, '_unparsed_exit_policy'):
    if descriptor._unparsed_exit_policy and stem.util.str_tools._to_unicode(descriptor._unparsed_exit_policy[0]) == 'reject *:*':
      descriptor.exit_policy = REJECT_ALL_POLICY
    else:
      descriptor.exit_policy = stem.exit_policy.ExitPolicy(*descriptor._unparsed_exit_policy)

    del descriptor._unparsed_exit_policy


_parse_identity_ed25519_line = Ed25519Certificate._from_descriptor('identity-ed25519', 'certificate')
_parse_master_key_ed25519_line = _parse_simple_line('master-key-ed25519', 'ed25519_master_key')
_parse_master_key_ed25519_for_hash_line = _parse_simple_line('master-key-ed25519', 'ed25519_certificate_hash')
_parse_contact_line = _parse_bytes_line('contact', 'contact')
_parse_published_line = _parse_timestamp_line('published', 'published')
_parse_read_history_line = functools.partial(_parse_history_line, 'read-history', 'read_history_end', 'read_history_interval', 'read_history_values')
_parse_write_history_line = functools.partial(_parse_history_line, 'write-history', 'write_history_end', 'write_history_interval', 'write_history_values')
_parse_ipv6_policy_line = _parse_simple_line('ipv6-policy', 'exit_policy_v6', func = lambda v: stem.exit_policy.MicroExitPolicy(v))
_parse_allow_single_hop_exits_line = _parse_if_present('allow-single-hop-exits', 'allow_single_hop_exits')
_parse_tunneled_dir_server_line = _parse_if_present('tunnelled-dir-server', 'allow_tunneled_dir_requests')
_parse_proto_line = _parse_protocol_line('proto', 'protocols')
_parse_hidden_service_dir_line = _parse_if_present('hidden-service-dir', 'is_hidden_service_dir')
_parse_caches_extra_info_line = _parse_if_present('caches-extra-info', 'extra_info_cache')
_parse_bridge_distribution_request_line = _parse_simple_line('bridge-distribution-request', 'bridge_distribution')
_parse_family_line = _parse_simple_line('family', 'family', func = lambda v: set(v.split(' ')))
_parse_eventdns_line = _parse_simple_line('eventdns', 'eventdns', func = lambda v: v == '1')
_parse_onion_key_line = _parse_key_block('onion-key', 'onion_key', 'RSA PUBLIC KEY')
_parse_onion_key_crosscert_line = _parse_key_block('onion-key-crosscert', 'onion_key_crosscert', 'CROSSCERT')
_parse_signing_key_line = _parse_key_block('signing-key', 'signing_key', 'RSA PUBLIC KEY')
_parse_router_signature_line = _parse_key_block('router-signature', 'signature', 'SIGNATURE')
_parse_ntor_onion_key_line = _parse_simple_line('ntor-onion-key', 'ntor_onion_key')
_parse_ntor_onion_key_crosscert_line = _parse_key_block('ntor-onion-key-crosscert', 'ntor_onion_key_crosscert', 'ED25519 CERT', 'ntor_onion_key_crosscert_sign')
_parse_router_sig_ed25519_line = _parse_simple_line('router-sig-ed25519', 'ed25519_signature')
_parse_router_digest_sha256_line = _parse_simple_line('router-digest-sha256', 'router_digest_sha256')
_parse_router_digest_line = _parse_forty_character_hex('router-digest', '_digest')

# TODO: We need to be tolerant of negative uptimes to accommodate a past tor
# bug...
#
# Changes in version 0.1.2.7-alpha - 2007-02-06
#  - If our system clock jumps back in time, don't publish a negative
#    uptime in the descriptor. Also, don't let the global rate limiting
#    buckets go absurdly negative.
#
# After parsing all of the attributes we'll double check that negative
# uptimes only occurred prior to this fix.

_parse_uptime_line = _parse_int_line('uptime', 'uptime', allow_negative = True)


class ServerDescriptor(Descriptor):
  """
  Common parent for server descriptors.

  :var str nickname: **\\*** relay's nickname
  :var str fingerprint: identity key fingerprint
  :var datetime published: **\\*** time in UTC when this descriptor was made

  :var str address: **\\*** IPv4 address of the relay
  :var int or_port: **\\*** port used for relaying
  :var int socks_port: **\\*** port used as client (**deprecated**, always **None**)
  :var int dir_port: **\\*** port used for descriptor mirroring

  :var bytes platform: line with operating system and tor version
  :var stem.version.Version tor_version: version of tor
  :var str operating_system: operating system
  :var int uptime: uptime when published in seconds
  :var bytes contact: contact information
  :var stem.exit_policy.ExitPolicy exit_policy: **\\*** stated exit policy
  :var stem.exit_policy.MicroExitPolicy exit_policy_v6: **\\*** exit policy for IPv6
  :var BridgeDistribution bridge_distribution: **\\*** preferred method of providing this relay's
    address if a bridge
  :var set family: **\\*** nicknames or fingerprints of declared family

  :var int average_bandwidth: **\\*** average rate it's willing to relay in bytes/s
  :var int burst_bandwidth: **\\*** burst rate it's willing to relay in bytes/s
  :var int observed_bandwidth: **\\*** estimated capacity based on usage in bytes/s

  :var list link_protocols: link protocols supported by the relay
  :var list circuit_protocols: circuit protocols supported by the relay
  :var bool is_hidden_service_dir: **\\*** indicates if the relay serves hidden
    service descriptors
  :var bool hibernating: **\\*** hibernating when published
  :var bool allow_single_hop_exits: **\\*** flag if single hop exiting is allowed
  :var bool allow_tunneled_dir_requests: **\\*** flag if tunneled directory
    requests are accepted
  :var bool extra_info_cache: **\\*** flag if a mirror for extra-info documents
  :var str extra_info_digest: upper-case hex encoded digest of our extra-info document
  :var str extra_info_sha256_digest: base64 encoded sha256 digest of our extra-info document
  :var bool eventdns: flag for evdns backend (**deprecated**, always unset)
  :var str ntor_onion_key: base64 key used to encrypt EXTEND in the ntor protocol
  :var list or_addresses: **\\*** alternative for our address/or_port
    attributes, each entry is a tuple of the form (address (**str**), port
    (**int**), is_ipv6 (**bool**))
  :var dict protocols: mapping of protocols to their supported versions

  **Deprecated**, moved to extra-info descriptor...

  :var datetime read_history_end: end of the sampling interval
  :var int read_history_interval: seconds per interval
  :var list read_history_values: bytes read during each interval

  :var datetime write_history_end: end of the sampling interval
  :var int write_history_interval: seconds per interval
  :var list write_history_values: bytes written during each interval

  **\\*** attribute is either required when we're parsed with validation or has
  a default value, others are left as **None** if undefined

  .. versionchanged:: 1.5.0
     Added the allow_tunneled_dir_requests attribute.

  .. versionchanged:: 1.6.0
     Added the extra_info_sha256_digest, protocols, and bridge_distribution
     attributes.

  .. versionchanged:: 1.7.0
     Added the is_hidden_service_dir attribute.
  """

  ATTRIBUTES = {
    'nickname': (None, _parse_router_line),
    'fingerprint': (None, _parse_fingerprint_line),
    'contact': (None, _parse_contact_line),
    'published': (None, _parse_published_line),
    'exit_policy': (None, _parse_exit_policy),

    'address': (None, _parse_router_line),
    'or_port': (None, _parse_router_line),
    'socks_port': (None, _parse_router_line),
    'dir_port': (None, _parse_router_line),

    'platform': (None, _parse_platform_line),
    'tor_version': (None, _parse_platform_line),
    'operating_system': (None, _parse_platform_line),
    'uptime': (None, _parse_uptime_line),
    'exit_policy_v6': (DEFAULT_IPV6_EXIT_POLICY, _parse_ipv6_policy_line),
    'bridge_distribution': (DEFAULT_BRIDGE_DISTRIBUTION, _parse_bridge_distribution_request_line),
    'family': (set(), _parse_family_line),

    'average_bandwidth': (None, _parse_bandwidth_line),
    'burst_bandwidth': (None, _parse_bandwidth_line),
    'observed_bandwidth': (None, _parse_bandwidth_line),

    'link_protocols': (None, _parse_protocols_line),
    'circuit_protocols': (None, _parse_protocols_line),
    'is_hidden_service_dir': (False, _parse_hidden_service_dir_line),
    'hibernating': (False, _parse_hibernating_line),
    'allow_single_hop_exits': (False, _parse_allow_single_hop_exits_line),
    'allow_tunneled_dir_requests': (False, _parse_tunneled_dir_server_line),
    'protocols': ({}, _parse_proto_line),
    'extra_info_cache': (False, _parse_caches_extra_info_line),
    'extra_info_digest': (None, _parse_extrainfo_digest_line),
    'extra_info_sha256_digest': (None, _parse_extrainfo_digest_line),
    'eventdns': (None, _parse_eventdns_line),
    'ntor_onion_key': (None, _parse_ntor_onion_key_line),
    'or_addresses': ([], _parse_or_address_line),

    'read_history_end': (None, _parse_read_history_line),
    'read_history_interval': (None, _parse_read_history_line),
    'read_history_values': (None, _parse_read_history_line),

    'write_history_end': (None, _parse_write_history_line),
    'write_history_interval': (None, _parse_write_history_line),
    'write_history_values': (None, _parse_write_history_line),
  }

  PARSER_FOR_LINE = {
    'router': _parse_router_line,
    'bandwidth': _parse_bandwidth_line,
    'platform': _parse_platform_line,
    'published': _parse_published_line,
    'fingerprint': _parse_fingerprint_line,
    'contact': _parse_contact_line,
    'hibernating': _parse_hibernating_line,
    'extra-info-digest': _parse_extrainfo_digest_line,
    'hidden-service-dir': _parse_hidden_service_dir_line,
    'uptime': _parse_uptime_line,
    'protocols': _parse_protocols_line,
    'ntor-onion-key': _parse_ntor_onion_key_line,
    'or-address': _parse_or_address_line,
    'read-history': _parse_read_history_line,
    'write-history': _parse_write_history_line,
    'ipv6-policy': _parse_ipv6_policy_line,
    'allow-single-hop-exits': _parse_allow_single_hop_exits_line,
    'tunnelled-dir-server': _parse_tunneled_dir_server_line,
    'proto': _parse_proto_line,
    'caches-extra-info': _parse_caches_extra_info_line,
    'bridge-distribution-request': _parse_bridge_distribution_request_line,
    'family': _parse_family_line,
    'eventdns': _parse_eventdns_line,
  }

  def __init__(self, raw_contents: bytes, validate: bool = False) -> None:
    """
    Server descriptor constructor, created from an individual relay's
    descriptor content (as provided by 'GETINFO desc/*', cached descriptors,
    and metrics).

    By default this validates the descriptor's content as it's parsed. This
    validation can be disables to either improve performance or be accepting of
    malformed data.

    :param raw_contents: descriptor content provided by the relay
    :param validate: checks the validity of the descriptor's content if
      **True**, skips these checks otherwise

    :raises: **ValueError** if the contents is malformed and validate is True
    """

    super(ServerDescriptor, self).__init__(raw_contents, lazy_load = not validate)

    # A descriptor contains a series of 'keyword lines' which are simply a
    # keyword followed by an optional value. Lines can also be followed by a
    # signature block.
    #
    # We care about the ordering of 'accept' and 'reject' entries because this
    # influences the resulting exit policy, but for everything else the order
    # does not matter so breaking it into key / value pairs.

    entries, self._unparsed_exit_policy = _descriptor_components_with_extra(raw_contents, validate, extra_keywords = ('accept', 'reject'), non_ascii_fields = ('contact', 'platform'))

    if validate:
      self._parse(entries, validate)

      _parse_exit_policy(self, entries)

      # if we have a negative uptime and a tor version that shouldn't exhibit
      # this bug then fail validation

      if validate and self.uptime and self.tor_version:
        if self.uptime < 0 and self.tor_version >= stem.version.Version('0.1.2.7'):
          raise ValueError("Descriptor for version '%s' had a negative uptime value: %i" % (self.tor_version, self.uptime))

      self._check_constraints(entries)
    else:
      self._entries = entries

  def digest(self, hash_type: 'stem.descriptor.DigestHash' = DigestHash.SHA1, encoding: 'stem.descriptor.DigestEncoding' = DigestEncoding.HEX) -> Union[str, 'hashlib._HASH']:  # type: ignore
    """
    Digest of this descriptor's content. These are referenced by...

      * **Consensus**

        * Referer: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3` **digest** attribute
        * Format: **SHA1/BASE64**

    .. versionchanged:: 1.8.0
       Added the hash_type and encoding arguments.

    :param hash_type: digest hashing algorithm
    :param encoding: digest encoding

    :returns: **hashlib.HASH** or **str** based on our encoding argument
    """

    raise NotImplementedError('Unsupported Operation: this should be implemented by the ServerDescriptor subclass')

  def _check_constraints(self, entries: ENTRY_TYPE) -> None:
    """
    Does a basic check that the entries conform to this descriptor type's
    constraints.

    :param entries: keyword => (value, pgp key) entries

    :raises: **ValueError** if an issue arises in validation
    """

    for keyword in self._required_fields():
      if keyword not in entries:
        raise ValueError("Descriptor must have a '%s' entry" % keyword)

    for keyword in self._single_fields():
      if keyword in entries and len(entries[keyword]) > 1:
        raise ValueError("The '%s' entry can only appear once in a descriptor" % keyword)

    expected_first_keyword = self._first_keyword()
    if expected_first_keyword and expected_first_keyword != list(entries.keys())[0]:
      raise ValueError("Descriptor must start with a '%s' entry" % expected_first_keyword)

    expected_last_keyword = self._last_keyword()
    if expected_last_keyword and expected_last_keyword != list(entries.keys())[-1]:
      raise ValueError("Descriptor must end with a '%s' entry" % expected_last_keyword)

    if 'identity-ed25519' in entries.keys():
      if 'router-sig-ed25519' not in entries.keys():
        raise ValueError('Descriptor must have router-sig-ed25519 entry to accompany identity-ed25519')
      elif 'router-sig-ed25519' not in list(entries.keys())[-2:]:
        raise ValueError("Descriptor must have 'router-sig-ed25519' as the next-to-last entry")

    if not self.exit_policy:
      raise ValueError("Descriptor must have at least one 'accept' or 'reject' entry")

  # Constraints that the descriptor must meet to be valid. These can be None if
  # not applicable.

  def _required_fields(self) -> Tuple[str, ...]:
    return REQUIRED_FIELDS

  def _single_fields(self) -> Tuple[str, ...]:
    return REQUIRED_FIELDS + SINGLE_FIELDS

  def _first_keyword(self) -> str:
    return 'router'

  def _last_keyword(self) -> Optional[str]:
    return 'router-signature'


class RelayDescriptor(ServerDescriptor):
  """
  Server descriptor (`descriptor specification
  <https://gitweb.torproject.org/torspec.git/tree/dir-spec.txt>`_)

  :var stem.certificate.Ed25519Certificate certificate: ed25519 certificate
  :var str ed25519_master_key: base64 encoded master key for our ed25519 certificate
  :var str ed25519_signature: signature of this document using ed25519

  :var str onion_key: **\\*** key used to encrypt EXTEND cells
  :var str onion_key_crosscert: signature generated using the onion_key
  :var str ntor_onion_key_crosscert: signature generated using the ntor-onion-key
  :var str ntor_onion_key_crosscert_sign: sign of the corresponding ed25519 public key
  :var str signing_key: **\\*** relay's long-term identity key
  :var str signature: **\\*** signature for this descriptor

  **\\*** attribute is required when we're parsed with validation

  .. versionchanged:: 1.5.0
     Added the ed25519_master_key, ed25519_signature,
     onion_key_crosscert, ntor_onion_key_crosscert, and
     ntor_onion_key_crosscert_sign attributes.

  .. versionchanged:: 1.6.0
     Moved from the deprecated `pycrypto
     <https://www.dlitz.net/software/pycrypto/>`_ module to `cryptography
     <https://pypi.org/project/cryptography/>`_ for validating signatures.

  .. versionchanged:: 1.6.0
     Added the certificate attribute.

  .. versionchanged:: 1.6.0
     Added the **skip_crypto_validation** constructor argument.
  """

  TYPE_ANNOTATION_NAME = 'server-descriptor'

  ATTRIBUTES = dict(ServerDescriptor.ATTRIBUTES, **{
    'certificate': (None, _parse_identity_ed25519_line),
    'ed25519_master_key': (None, _parse_master_key_ed25519_line),
    'ed25519_signature': (None, _parse_router_sig_ed25519_line),

    'onion_key': (None, _parse_onion_key_line),
    'onion_key_crosscert': (None, _parse_onion_key_crosscert_line),
    'ntor_onion_key_crosscert': (None, _parse_ntor_onion_key_crosscert_line),
    'ntor_onion_key_crosscert_sign': (None, _parse_ntor_onion_key_crosscert_line),
    'signing_key': (None, _parse_signing_key_line),
    'signature': (None, _parse_router_signature_line),
  })

  PARSER_FOR_LINE = dict(ServerDescriptor.PARSER_FOR_LINE, **{
    'identity-ed25519': _parse_identity_ed25519_line,
    'master-key-ed25519': _parse_master_key_ed25519_line,
    'router-sig-ed25519': _parse_router_sig_ed25519_line,
    'onion-key': _parse_onion_key_line,
    'onion-key-crosscert': _parse_onion_key_crosscert_line,
    'ntor-onion-key-crosscert': _parse_ntor_onion_key_crosscert_line,
    'signing-key': _parse_signing_key_line,
    'router-signature': _parse_router_signature_line,
  })

  def __init__(self, raw_contents: bytes, validate: bool = False, skip_crypto_validation: bool = False) -> None:
    super(RelayDescriptor, self).__init__(raw_contents, validate)

    if validate:
      if not skip_crypto_validation:
        if self.fingerprint:
          key_hash = hashlib.sha1(_bytes_for_block(self.signing_key)).hexdigest()

          if key_hash != self.fingerprint.lower():
            raise ValueError('Fingerprint does not match the hash of our signing key (fingerprint: %s, signing key hash: %s)' % (self.fingerprint.lower(), key_hash))

        try:
          signed_digest = self._digest_for_signature(self.signing_key, self.signature)


          # When signing, the cryptography module includes a constant prefix
          # indicating the hash algorithm used. Tor doesn't. This causes
          # signature validation failures and unfortunately cryptography have
          # no nice way of excluding these. To work around this, we only
          # validate that the digest ends with the correct suffix.
          #
          #   https://github.com/pyca/cryptography/issues/3713
          #
          if not signed_digest.endswith(self.digest()):
            raise ValueError('Decrypted digest does not match local digest (calculated: %s, local: %s)' % (signed_digest, self.digest()))

          if self.onion_key_crosscert:
            onion_key_crosscert_digest = self._digest_for_signature(self.onion_key, self.onion_key_crosscert)

            if onion_key_crosscert_digest != self._onion_key_crosscert_digest():
              raise ValueError('Decrypted onion-key-crosscert digest does not match local digest (calculated: %s, local: %s)' % (onion_key_crosscert_digest, self._onion_key_crosscert_digest()))
        except ImportError:
          pass  # cryptography module unavailable

      if self.certificate:
        try:
          self.certificate.validate(self)
        except ImportError:
          pass  # cryptography module unavailable

  @classmethod
  def content(cls: Type['stem.descriptor.server_descriptor.RelayDescriptor'], attr: Optional[Mapping[str, str]] = None, exclude: Sequence[str] = (), sign: bool = False, signing_key: Optional['stem.descriptor.SigningKey'] = None, exit_policy: Optional['stem.exit_policy.ExitPolicy'] = None) -> bytes:
    attr = dict(attr) if attr else {}

    if exit_policy is None:
      exit_policy = REJECT_ALL_POLICY

    base_header = [
      ('router', '%s %s 9001 0 0' % (_random_nickname(), _random_ipv4_address())),
      ('published', _random_date()),
      ('bandwidth', '153600 256000 104590'),
    ] + [
      tuple(line.split(' ', 1)) for line in str(exit_policy).splitlines()  # type: ignore
    ] + [
      ('onion-key', _random_crypto_blob('RSA PUBLIC KEY')),
      ('signing-key', _random_crypto_blob('RSA PUBLIC KEY')),
    ]

    if sign or signing_key:
      if attr and 'signing-key' in attr:
        raise ValueError('Cannot sign the descriptor if a signing-key has been provided')
      elif attr and 'router-signature' in attr:
        raise ValueError('Cannot sign the descriptor if a router-signature has been provided')

      if signing_key is None:
        signing_key = create_signing_key()

      if 'fingerprint' not in attr:
        fingerprint = hashlib.sha1(_bytes_for_block(stem.util.str_tools._to_unicode(signing_key.public_digest.strip()))).hexdigest().upper()
        attr['fingerprint'] = ' '.join(stem.util.str_tools._split_by_length(fingerprint, 4))

      attr['signing-key'] = signing_key.public_digest

      content = _descriptor_content(attr, exclude, base_header) + b'\nrouter-signature\n'
      return _append_router_signature(content, signing_key.private)
    else:
      return _descriptor_content(attr, exclude, base_header, (
        ('router-sig-ed25519', None),
        ('router-signature', _random_crypto_blob('SIGNATURE')),
      ))

  @classmethod
  def create(cls: Type['stem.descriptor.server_descriptor.RelayDescriptor'], attr: Optional[Mapping[str, str]] = None, exclude: Sequence[str] = (), validate: bool = True, sign: bool = False, signing_key: Optional['stem.descriptor.SigningKey'] = None, exit_policy: Optional['stem.exit_policy.ExitPolicy'] = None) -> 'stem.descriptor.server_descriptor.RelayDescriptor':
    return cls(cls.content(attr, exclude, sign, signing_key, exit_policy), validate = validate, skip_crypto_validation = not sign)

  @functools.lru_cache()
  def digest(self, hash_type: 'stem.descriptor.DigestHash' = DigestHash.SHA1, encoding: 'stem.descriptor.DigestEncoding' = DigestEncoding.HEX) -> Union[str, 'hashlib._HASH']:  # type: ignore
    """
    Provides the digest of our descriptor's content.

    :param hash_type: digest hashing algorithm
    :param encoding: digest encoding

    :returns: **hashlib.HASH** or **str** based on our encoding argument

    :raises: ValueError if the digest cannot be calculated
    """

    content = self._content_range(start = 'router', end = '\nrouter-signature\n')

    if hash_type == DigestHash.SHA1:
      return stem.descriptor._encode_digest(hashlib.sha1(content), encoding)
    elif hash_type == DigestHash.SHA256:
      return stem.descriptor._encode_digest(hashlib.sha256(content), encoding)
    else:
      raise NotImplementedError('Server descriptor digests are only available in sha1 and sha256, not %s' % hash_type)

  def make_router_status_entry(self) -> 'stem.descriptor.router_status_entry.RouterStatusEntryV3':
    """
    Provides a RouterStatusEntryV3 for this descriptor content.

    .. versionadded:: 1.6.0

    :returns: :class:`~stem.descriptor.router_status_entry.RouterStatusEntryV3`
      that would be in the consensus
    """

    if not self.fingerprint:
      raise ValueError('Server descriptor lacks a fingerprint. This is an optional field, but required to make a router status entry.')

    attr = {
      'r': ' '.join([
        self.nickname,
        _truncated_b64encode(binascii.unhexlify(stem.util.str_tools._to_bytes(self.fingerprint))),
        _truncated_b64encode(binascii.unhexlify(stem.util.str_tools._to_bytes(self.digest()))),
        self.published.strftime('%Y-%m-%d %H:%M:%S'),
        self.address,
        str(self.or_port),
        str(self.dir_port) if self.dir_port else '0',
      ]),
      'w': 'Bandwidth=%i' % self.average_bandwidth,
      'p': self.exit_policy.summary().replace(', ', ','),
    }

    if self.tor_version:
      attr['v'] = 'Tor %s' % self.tor_version

    if self.or_addresses:
      attr['a'] = ['%s:%s' % (addr, port) for addr, port, _ in self.or_addresses]

    if self.certificate:
      attr['id'] = 'ed25519 %s' % _truncated_b64encode(self.certificate.key)

    return RouterStatusEntryV3.create(attr)  # type: ignore

  @functools.lru_cache()
  def _onion_key_crosscert_digest(self) -> str:
    """
    Provides the digest of the onion-key-crosscert data. This consists of the
    RSA identity key sha1 and ed25519 identity key.

    :returns: **str** digest encoded in uppercase hex

    :raises: ValueError if the digest cannot be calculated
    """

    signing_key_digest = hashlib.sha1(_bytes_for_block(self.signing_key)).digest()
    data = signing_key_digest + base64.b64decode(stem.util.str_tools._to_bytes(self.ed25519_master_key) + b'=')
    return stem.util.str_tools._to_unicode(binascii.hexlify(data).upper())

  def _check_constraints(self, entries: ENTRY_TYPE) -> None:
    super(RelayDescriptor, self)._check_constraints(entries)

    if self.certificate:
      if not self.onion_key_crosscert:
        raise ValueError("Descriptor must have a 'onion-key-crosscert' when identity-ed25519 is present")
      elif not self.ed25519_signature:
        raise ValueError("Descriptor must have a 'router-sig-ed25519' when identity-ed25519 is present")


class BridgeDescriptor(ServerDescriptor):
  """
  Bridge descriptor (`bridge descriptor specification
  <https://metrics.torproject.org/collector.html#bridge-descriptors>`_)

  :var str ed25519_certificate_hash: sha256 hash of the original identity-ed25519
  :var str router_digest_sha256: sha256 digest of this document

  .. versionchanged:: 1.5.0
     Added the ed25519_certificate_hash and router_digest_sha256 attributes.
     Also added ntor_onion_key (previously this only belonged to unsanitized
     descriptors).
  """

  TYPE_ANNOTATION_NAME = 'bridge-server-descriptor'

  ATTRIBUTES = dict(ServerDescriptor.ATTRIBUTES, **{
    'ed25519_certificate_hash': (None, _parse_master_key_ed25519_for_hash_line),
    'router_digest_sha256': (None, _parse_router_digest_sha256_line),
    '_digest': (None, _parse_router_digest_line),
  })

  PARSER_FOR_LINE = dict(ServerDescriptor.PARSER_FOR_LINE, **{
    'master-key-ed25519': _parse_master_key_ed25519_for_hash_line,
    'router-digest-sha256': _parse_router_digest_sha256_line,
    'router-digest': _parse_router_digest_line,
  })

  @classmethod
  def content(cls: Type['stem.descriptor.server_descriptor.BridgeDescriptor'], attr: Optional[Mapping[str, str]] = None, exclude: Sequence[str] = ()) -> bytes:
    return _descriptor_content(attr, exclude, (
      ('router', '%s %s 9001 0 0' % (_random_nickname(), _random_ipv4_address())),
      ('router-digest', '006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4'),
      ('published', _random_date()),
      ('bandwidth', '409600 819200 5120'),
      ('reject', '*:*'),
    ))

  def digest(self, hash_type: 'stem.descriptor.DigestHash' = DigestHash.SHA1, encoding: 'stem.descriptor.DigestEncoding' = DigestEncoding.HEX) -> Union[str, 'hashlib._HASH']:  # type: ignore
    if hash_type == DigestHash.SHA1 and encoding == DigestEncoding.HEX:
      return self._digest
    else:
      raise NotImplementedError('Bridge server descriptor digests are only available as sha1/hex, not %s/%s' % (hash_type, encoding))

  def is_scrubbed(self) -> bool:
    """
    Checks if we've been properly scrubbed in accordance with the `bridge
    descriptor specification
    <https://metrics.torproject.org/collector.html#bridge-descriptors>`_.
    Validation is a moving target so this may not be fully up to date.

    :returns: **True** if we're scrubbed, **False** otherwise
    """

    return self.get_scrubbing_issues() == []

  @functools.lru_cache()
  def get_scrubbing_issues(self) -> Sequence[str]:
    """
    Provides issues with our scrubbing.

    :returns: **list** of strings which describe issues we have with our
      scrubbing, this list is empty if we're properly scrubbed
    """

    issues = []

    if not self.address.startswith('10.'):
      issues.append("Router line's address should be scrubbed to be '10.x.x.x': %s" % self.address)

    if self.contact and self.contact != 'somebody':
      issues.append("Contact line should be scrubbed to be 'somebody', but instead had '%s'" % self.contact)

    for address, _, is_ipv6 in self.or_addresses:
      if not is_ipv6 and not address.startswith('10.'):
        issues.append("or-address line's address should be scrubbed to be '10.x.x.x': %s" % address)
      elif is_ipv6 and not address.startswith('fd9f:2e19:3bcf::'):
        # TODO: this check isn't quite right because we aren't checking that
        # the next grouping of hex digits contains 1-2 digits
        issues.append("or-address line's address should be scrubbed to be 'fd9f:2e19:3bcf::xx:xxxx': %s" % address)

    for line in self.get_unrecognized_lines():
      if line.startswith('onion-key '):
        issues.append('Bridge descriptors should have their onion-key scrubbed: %s' % line)
      elif line.startswith('signing-key '):
        issues.append('Bridge descriptors should have their signing-key scrubbed: %s' % line)
      elif line.startswith('router-signature '):
        issues.append('Bridge descriptors should have their signature scrubbed: %s' % line)

    return issues

  def _required_fields(self) -> Tuple[str, ...]:
    # bridge required fields are the same as a relay descriptor, minus items
    # excluded according to the format page

    excluded_fields = [
      'onion-key',
      'signing-key',
      'router-signature',
    ]

    included_fields = [
      'router-digest',
    ]

    return tuple(included_fields + [f for f in REQUIRED_FIELDS if f not in excluded_fields])

  def _single_fields(self) -> Tuple[str, ...]:
    return self._required_fields() + SINGLE_FIELDS

  def _last_keyword(self) -> Optional[str]:
    return None
