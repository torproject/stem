# Copyright 2012-2016, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Helper functions for creating mock objects.

::

  get_all_combinations - provides all combinations of attributes

  Instance Constructors
    get_message                     - stem.response.ControlMessage
    get_protocolinfo_response       - stem.response.protocolinfo.ProtocolInfoResponse

    stem.descriptor.server_descriptor
      get_relay_server_descriptor  - RelayDescriptor
      get_bridge_server_descriptor - BridgeDescriptor

    stem.descriptor.microdescriptor
      get_microdescriptor - Microdescriptor

    stem.descriptor.extrainfo_descriptor
      get_relay_extrainfo_descriptor  - RelayExtraInfoDescriptor
      get_bridge_extrainfo_descriptor - BridgeExtraInfoDescriptor

    stem.descriptor.networkstatus
      get_directory_authority        - DirectoryAuthority
      get_key_certificate            - KeyCertificate
      get_network_status_document_v2 - NetworkStatusDocumentV2
      get_network_status_document_v3 - NetworkStatusDocumentV3

    stem.descriptor.router_status_entry
      get_router_status_entry_v2       - RouterStatusEntryV2
      get_router_status_entry_v3       - RouterStatusEntryV3
      get_router_status_entry_micro_v3 - RouterStatusEntryMicroV3

    stem.descriptor.hidden-service_descriptor
      get_hidden_service_descriptor - HiddenServiceDescriptor
"""

import base64
import hashlib
import itertools
import re
import textwrap

import stem.descriptor.extrainfo_descriptor
import stem.descriptor.hidden_service_descriptor
import stem.descriptor.microdescriptor
import stem.descriptor.networkstatus
import stem.descriptor.router_status_entry
import stem.descriptor.server_descriptor
import stem.prereq
import stem.response
import stem.util.str_tools

try:
  # added in python 3.3
  from unittest.mock import Mock, patch
except ImportError:
  from mock import Mock, patch

try:
  # added in python 2.7
  from collections import OrderedDict
except ImportError:
  from stem.util.ordereddict import OrderedDict

CRYPTO_BLOB = """
MIGJAoGBAJv5IIWQ+WDWYUdyA/0L8qbIkEVH/cwryZWoIaPAzINfrw1WfNZGtBmg
skFtXhOHHqTRN4GPPrZsAIUOQGzQtGb66IQgT4tO/pj+P6QmSCCdTfhvGfgTCsC+
WPi4Fl2qryzTb3QO5r5x7T8OsG2IBUET1bLQzmtbC560SYR49IvVAgMBAAE=
"""

DOC_SIG = stem.descriptor.networkstatus.DocumentSignature(
  'sha1',
  '14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4',
  'BF112F1C6D5543CFD0A32215ACABD4197B5279AD',
  '-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB)

RELAY_SERVER_HEADER = (
  ('router', 'caerSidi 71.35.133.197 9001 0 0'),
  ('published', '2012-03-01 17:15:27'),
  ('bandwidth', '153600 256000 104590'),
  ('reject', '*:*'),
  ('onion-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
  ('signing-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
)

RELAY_SERVER_FOOTER = (
  ('router-signature', '\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB),
)

BRIDGE_SERVER_HEADER = (
  ('router', 'Unnamed 10.45.227.253 9001 0 0'),
  ('router-digest', '006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4'),
  ('published', '2012-03-22 17:34:38'),
  ('bandwidth', '409600 819200 5120'),
  ('reject', '*:*'),
)

RELAY_EXTRAINFO_HEADER = (
  ('extra-info', 'ninja B2289C3EAB83ECD6EB916A2F481A02E6B76A0A48'),
  ('published', '2012-05-05 17:03:50'),
)

RELAY_EXTRAINFO_FOOTER = (
  ('router-signature', '\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB),
)

BRIDGE_EXTRAINFO_HEADER = (
  ('extra-info', 'ec2bridgereaac65a3 1EC248422B57D9C0BD751892FE787585407479A4'),
  ('published', '2012-05-05 17:03:50'),
)

BRIDGE_EXTRAINFO_FOOTER = (
  ('router-digest', '006FD96BA35E7785A6A3B8B75FE2E2435A13BDB4'),
)

MICRODESCRIPTOR = (
  ('onion-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
)

ROUTER_STATUS_ENTRY_V2_HEADER = (
  ('r', 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0'),
)

ROUTER_STATUS_ENTRY_V3_HEADER = (
  ('r', 'caerSidi p1aag7VwarGxqctS7/fS0y5FU+s oQZFLYe9e4A7bOkWKR7TaNxb0JE 2012-08-06 11:19:31 71.35.150.29 9001 0'),
  ('s', 'Fast Named Running Stable Valid'),
)

ROUTER_STATUS_ENTRY_MICRO_V3_HEADER = (
  ('r', 'Konata ARIJF2zbqirB9IwsW0mQznccWww 2012-09-24 13:40:40 69.64.48.168 9001 9030'),
  ('m', 'aiUklwBrua82obG5AsTX+iEpkjQA2+AQHxZ7GwMfY70'),
  ('s', 'Fast Guard HSDir Named Running Stable V2Dir Valid'),
)

AUTHORITY_HEADER = (
  ('dir-source', 'turtles 27B6B5996C426270A5C95488AA5BCEB6BCC86956 no.place.com 76.73.17.194 9030 9090'),
  ('contact', 'Mike Perry <email>'),
)

KEY_CERTIFICATE_HEADER = (
  ('dir-key-certificate-version', '3'),
  ('fingerprint', '27B6B5996C426270A5C95488AA5BCEB6BCC86956'),
  ('dir-key-published', '2011-11-28 21:51:04'),
  ('dir-key-expires', '2012-11-28 21:51:04'),
  ('dir-identity-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
  ('dir-signing-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
)

KEY_CERTIFICATE_FOOTER = (
  ('dir-key-certification', '\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB),
)

NETWORK_STATUS_DOCUMENT_HEADER_V2 = (
  ('network-status-version', '2'),
  ('dir-source', '18.244.0.114 18.244.0.114 80'),
  ('fingerprint', '719BE45DE224B607C53707D0E2143E2D423E74CF'),
  ('contact', 'arma at mit dot edu'),
  ('published', '2005-12-16 00:13:46'),
  ('dir-signing-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
)

NETWORK_STATUS_DOCUMENT_FOOTER_V2 = (
  ('directory-signature', 'moria2\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB),
)

NETWORK_STATUS_DOCUMENT_HEADER = (
  ('network-status-version', '3'),
  ('vote-status', 'consensus'),
  ('consensus-methods', None),
  ('consensus-method', None),
  ('published', None),
  ('valid-after', '2012-09-02 22:00:00'),
  ('fresh-until', '2012-09-02 22:00:00'),
  ('valid-until', '2012-09-02 22:00:00'),
  ('voting-delay', '300 300'),
  ('client-versions', None),
  ('server-versions', None),
  ('package', None),
  ('known-flags', 'Authority BadExit Exit Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid'),
  ('params', None),
)

NETWORK_STATUS_DOCUMENT_FOOTER = (
  ('directory-footer', ''),
  ('bandwidth-weights', None),
  ('directory-signature', '%s %s\n%s' % (DOC_SIG.identity, DOC_SIG.key_digest, DOC_SIG.signature)),
)

HIDDEN_SERVICE_HEADER = (
  ('rendezvous-service-descriptor', 'y3olqqblqw2gbh6phimfuiroechjjafa'),
  ('version', '2'),
  ('permanent-key', '\n-----BEGIN RSA PUBLIC KEY-----%s-----END RSA PUBLIC KEY-----' % CRYPTO_BLOB),
  ('secret-id-part', 'e24kgecavwsznj7gpbktqsiwgvngsf4e'),
  ('publication-time', '2015-02-23 20:00:00'),
  ('protocol-versions', '2,3'),
  ('introduction-points', '\n-----BEGIN MESSAGE-----\n-----END MESSAGE-----'),
)

HIDDEN_SERVICE_FOOTER = (
  ('signature', '\n-----BEGIN SIGNATURE-----%s-----END SIGNATURE-----' % CRYPTO_BLOB),
)


def get_all_combinations(attr, include_empty = False):
  """
  Provides an iterator for all combinations of a set of attributes. For
  instance...

  ::

    >>> list(test.mocking.get_all_combinations(['a', 'b', 'c']))
    [('a',), ('b',), ('c',), ('a', 'b'), ('a', 'c'), ('b', 'c'), ('a', 'b', 'c')]

  :param list attr: attributes to provide combinations for
  :param bool include_empty: includes an entry with zero items if True
  :returns: iterator for all combinations
  """

  # Makes an itertools.product() call for 'i' copies of attr...
  #
  # * itertools.product(attr) => all one-element combinations
  # * itertools.product(attr, attr) => all two-element combinations
  # * ... etc

  if include_empty:
    yield ()

  seen = set()
  for index in range(1, len(attr) + 1):
    product_arg = [attr for _ in range(index)]

    for item in itertools.product(*product_arg):
      # deduplicate, sort, and only provide if we haven't seen it yet
      item = tuple(sorted(set(item)))

      if item not in seen:
        seen.add(item)
        yield item


def get_message(content, reformat = True):
  """
  Provides a ControlMessage with content modified to be parsable. This makes
  the following changes unless 'reformat' is false...

  * ensures the content ends with a newline
  * newlines are replaced with a carriage return and newline pair

  :param str content: base content for the controller message
  :param str reformat: modifies content to be more accommodating to being parsed

  :returns: stem.response.ControlMessage instance
  """

  if reformat:
    if not content.endswith('\n'):
      content += '\n'

    content = re.sub('([\r]?)\n', '\r\n', content)

  return stem.response.ControlMessage.from_str(content)


def get_protocolinfo_response(**attributes):
  """
  Provides a ProtocolInfoResponse, customized with the given attributes. The
  base instance is minimal, with its version set to one and everything else
  left with the default.

  :param dict attributes: attributes to customize the response with

  :returns: stem.response.protocolinfo.ProtocolInfoResponse instance
  """

  protocolinfo_response = get_message('250-PROTOCOLINFO 1\n250 OK')
  stem.response.convert('PROTOCOLINFO', protocolinfo_response)

  for attr in attributes:
    setattr(protocolinfo_response, attr, attributes[attr])

  return protocolinfo_response


def _get_descriptor_content(attr = None, exclude = (), header_template = (), footer_template = ()):
  """
  Constructs a minimal descriptor with the given attributes. The content we
  provide back is of the form...

  * header_template (with matching attr filled in)
  * unused attr entries
  * footer_template (with matching attr filled in)

  So for instance...

  ::

    get_descriptor_content(
      attr = {'nickname': 'caerSidi', 'contact': 'atagar'},
      header_template = (
        ('nickname', 'foobar'),
        ('fingerprint', '12345'),
      ),
    )

  ... would result in...

  ::

    nickname caerSidi
    fingerprint 12345
    contact atagar

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param tuple header_template: key/value pairs for mandatory fields before unrecognized content
  :param tuple footer_template: key/value pairs for mandatory fields after unrecognized content

  :returns: str with the requested descriptor content
  """

  header_content, footer_content = [], []
  attr = {} if attr is None else dict(attr)

  attr = OrderedDict(attr)  # shallow copy since we're destructive

  for content, template in ((header_content, header_template),
                            (footer_content, footer_template)):
    for keyword, value in template:
      if keyword in exclude:
        continue
      elif keyword in attr:
        value = attr[keyword]
        del attr[keyword]

      if value is None:
        continue
      elif value == '':
        content.append(keyword)
      elif keyword == 'onion-key' or keyword == 'signing-key' or keyword == 'router-signature':
        content.append('%s%s' % (keyword, value))
      else:
        content.append('%s %s' % (keyword, value))

  remainder = []

  for k, v in attr.items():
    if v:
      remainder.append('%s %s' % (k, v))
    else:
      remainder.append(k)

  return stem.util.str_tools._to_bytes('\n'.join(header_content + remainder + footer_content))


def get_relay_server_descriptor(attr = None, exclude = (), content = False, sign_content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.server_descriptor.RelayDescriptor

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  :param bool sign_content: sets a proper digest value if True

  :returns: RelayDescriptor for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, RELAY_SERVER_HEADER, RELAY_SERVER_FOOTER)

  if content:
    return desc_content
  else:
    if sign_content:
      desc_content = sign_descriptor_content(desc_content)

    with patch('stem.prereq.is_crypto_available', Mock(return_value = False)):
      desc = stem.descriptor.server_descriptor.RelayDescriptor(desc_content, validate = True)

    return desc


def get_bridge_server_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.server_descriptor.BridgeDescriptor

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: BridgeDescriptor for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, BRIDGE_SERVER_HEADER)

  if content:
    return desc_content
  else:
    return stem.descriptor.server_descriptor.BridgeDescriptor(desc_content, validate = True)


def get_relay_extrainfo_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: RelayExtraInfoDescriptor for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, RELAY_EXTRAINFO_HEADER, RELAY_EXTRAINFO_FOOTER)

  if content:
    return desc_content
  else:
    return stem.descriptor.extrainfo_descriptor.RelayExtraInfoDescriptor(desc_content, validate = True)


def get_bridge_extrainfo_descriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: BridgeExtraInfoDescriptor for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, BRIDGE_EXTRAINFO_HEADER, BRIDGE_EXTRAINFO_FOOTER)

  if content:
    return desc_content
  else:
    return stem.descriptor.extrainfo_descriptor.BridgeExtraInfoDescriptor(desc_content, validate = True)


def get_microdescriptor(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.microdescriptor.Microdescriptor

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: Microdescriptor for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, MICRODESCRIPTOR)

  if content:
    return desc_content
  else:
    return stem.descriptor.microdescriptor.Microdescriptor(desc_content, validate = True)


def get_router_status_entry_v2(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.router_status_entry.RouterStatusEntryV2

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: RouterStatusEntryV2 for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, ROUTER_STATUS_ENTRY_V2_HEADER)

  if content:
    return desc_content
  else:
    return stem.descriptor.router_status_entry.RouterStatusEntryV2(desc_content, validate = True)


def get_router_status_entry_v3(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.router_status_entry.RouterStatusEntryV3

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: RouterStatusEntryV3 for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, ROUTER_STATUS_ENTRY_V3_HEADER)

  if content:
    return desc_content
  else:
    return stem.descriptor.router_status_entry.RouterStatusEntryV3(desc_content, validate = True)


def get_router_status_entry_micro_v3(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.router_status_entry.RouterStatusEntryMicroV3

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: RouterStatusEntryMicroV3 for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, ROUTER_STATUS_ENTRY_MICRO_V3_HEADER)

  if content:
    return desc_content
  else:
    return stem.descriptor.router_status_entry.RouterStatusEntryMicroV3(desc_content, validate = True)


def get_hidden_service_descriptor(attr = None, exclude = (), content = False, introduction_points_lines = None):
  """
  Provides the descriptor content for...
  stem.descriptor.hidden_service_descriptor.HidenServiceDescriptor

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True
  :param list introduction_points_lines: lines to be included in the introduction-points field

  :returns: HidenServiceDescriptor for the requested descriptor content
  """

  if (not attr or 'introduction-points' not in attr) and introduction_points_lines is not None:
    encoded = base64.b64encode(introduction_points_lines('\n'))
    attr['introduction-points'] = '\n-----BEGIN MESSAGE-----\n%s\n-----END MESSAGE-----' % '\n'.join(textwrap.wrap(encoded, 64))

  desc_content = _get_descriptor_content(attr, exclude, HIDDEN_SERVICE_HEADER, HIDDEN_SERVICE_FOOTER)

  if content:
    return desc_content
  else:
    with patch('stem.prereq.is_crypto_available', Mock(return_value = False)):
      return stem.descriptor.hidden_service_descriptor.HiddenServiceDescriptor(desc_content, validate = True)


def get_directory_authority(attr = None, exclude = (), is_vote = False, content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.DirectoryAuthority

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool is_vote: True if this is for a vote, False if it's for a consensus
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: DirectoryAuthority for the requested descriptor content
  """

  attr = {} if attr is None else dict(attr)

  if not is_vote:
    # entries from a consensus also have a mandatory 'vote-digest' field
    if not ('vote-digest' in attr or (exclude and 'vote-digest' in exclude)):
      attr['vote-digest'] = '0B6D1E9A300B895AA2D0B427F92917B6995C3C1C'

  desc_content = _get_descriptor_content(attr, exclude, AUTHORITY_HEADER)

  if is_vote:
    desc_content += b'\n' + get_key_certificate(content = True)

  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.DirectoryAuthority(desc_content, validate = True, is_vote = is_vote)


def get_key_certificate(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.KeyCertificate

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: KeyCertificate for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, KEY_CERTIFICATE_HEADER, KEY_CERTIFICATE_FOOTER)

  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.KeyCertificate(desc_content, validate = True)


def get_network_status_document_v2(attr = None, exclude = (), content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.NetworkStatusDocumentV2

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: NetworkStatusDocumentV2 for the requested descriptor content
  """

  desc_content = _get_descriptor_content(attr, exclude, NETWORK_STATUS_DOCUMENT_HEADER_V2, NETWORK_STATUS_DOCUMENT_FOOTER_V2)

  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.NetworkStatusDocumentV2(desc_content, validate = True)


def get_network_status_document_v3(attr = None, exclude = (), authorities = None, routers = None, content = False):
  """
  Provides the descriptor content for...
  stem.descriptor.networkstatus.NetworkStatusDocumentV3

  :param dict attr: keyword/value mappings to be included in the descriptor
  :param list exclude: mandatory keywords to exclude from the descriptor
  :param list authorities: directory authorities to include in the document
  :param list routers: router status entries to include in the document
  :param bool content: provides the str content of the descriptor rather than the class if True

  :returns: NetworkStatusDocumentV3 for the requested descriptor content
  """

  attr = {} if attr is None else dict(attr)

  # add defaults only found in a vote, consensus, or microdescriptor

  if attr.get('vote-status') == 'vote':
    extra_defaults = {
      'consensus-methods': '1 9',
      'published': '2012-09-02 22:00:00',
    }

    # votes need an authority to be valid

    if authorities is None:
      authorities = [get_directory_authority(is_vote = True)]
  else:
    extra_defaults = {
      'consensus-method': '9',
    }

  for k, v in extra_defaults.items():
    if exclude and k in exclude:
      continue  # explicitly excluding this field
    elif k not in attr:
      attr[k] = v

  desc_content = _get_descriptor_content(attr, exclude, NETWORK_STATUS_DOCUMENT_HEADER, NETWORK_STATUS_DOCUMENT_FOOTER)

  # inject the authorities and/or routers between the header and footer
  if authorities:
    if b'directory-footer' in desc_content:
      footer_div = desc_content.find(b'\ndirectory-footer') + 1
    elif b'directory-signature' in desc_content:
      footer_div = desc_content.find(b'\ndirectory-signature') + 1
    else:
      if routers:
        desc_content += b'\n'

      footer_div = len(desc_content) + 1

    authority_content = stem.util.str_tools._to_bytes('\n'.join([str(a) for a in authorities]) + '\n')
    desc_content = desc_content[:footer_div] + authority_content + desc_content[footer_div:]

  if routers:
    if b'directory-footer' in desc_content:
      footer_div = desc_content.find(b'\ndirectory-footer') + 1
    elif b'directory-signature' in desc_content:
      footer_div = desc_content.find(b'\ndirectory-signature') + 1
    else:
      if routers:
        desc_content += b'\n'

      footer_div = len(desc_content) + 1

    router_content = stem.util.str_tools._to_bytes('\n'.join([str(r) for r in routers]) + '\n')
    desc_content = desc_content[:footer_div] + router_content + desc_content[footer_div:]

  if content:
    return desc_content
  else:
    return stem.descriptor.networkstatus.NetworkStatusDocumentV3(desc_content, validate = True)


def sign_descriptor_content(desc_content):
  """
  Add a valid signature to the supplied descriptor string.

  If pycrypto is available the function will generate a key pair, and use it to
  sign the descriptor string. Any existing fingerprint, signing-key or
  router-signature data will be overwritten. If the library's unavailable the
  code will return the unaltered descriptor.

  :param str desc_content: the descriptor string to sign
  :returns: a descriptor string, signed if crypto available and unaltered otherwise
  """

  if not stem.prereq.is_crypto_available():
    return desc_content
  else:
    from Crypto.PublicKey import RSA
    from Crypto.Util import asn1
    from Crypto.Util.number import long_to_bytes

    # generate a key
    private_key = RSA.generate(1024)

    # get a string representation of the public key
    seq = asn1.DerSequence()
    seq.append(private_key.n)
    seq.append(private_key.e)
    seq_as_string = seq.encode()
    public_key_string = base64.b64encode(seq_as_string)

    # split public key into lines 64 characters long
    public_key_string = b'\n'.join([
      public_key_string[:64],
      public_key_string[64:128],
      public_key_string[128:],
    ])

    # generate the new signing key string

    signing_key_token = b'\nsigning-key\n'  # note the trailing '\n' is important here so as not to match the string elsewhere
    signing_key_token_start = b'-----BEGIN RSA PUBLIC KEY-----\n'
    signing_key_token_end = b'\n-----END RSA PUBLIC KEY-----\n'
    new_sk = signing_key_token + signing_key_token_start + public_key_string + signing_key_token_end

    # update the descriptor string with the new signing key

    skt_start = desc_content.find(signing_key_token)
    skt_end = desc_content.find(signing_key_token_end, skt_start)
    desc_content = desc_content[:skt_start] + new_sk + desc_content[skt_end + len(signing_key_token_end):]

    # generate the new fingerprint string

    key_hash = stem.util.str_tools._to_bytes(hashlib.sha1(seq_as_string).hexdigest().upper())
    grouped_fingerprint = b''

    for x in range(0, len(key_hash), 4):
      grouped_fingerprint += b' ' + key_hash[x:x + 4]
      fingerprint_token = b'\nfingerprint'
      new_fp = fingerprint_token + grouped_fingerprint

    # update the descriptor string with the new fingerprint

    ft_start = desc_content.find(fingerprint_token)
    if ft_start < 0:
      fingerprint_token = b'\nopt fingerprint'
      ft_start = desc_content.find(fingerprint_token)

    # if the descriptor does not already contain a fingerprint do not add one

    if ft_start >= 0:
      ft_end = desc_content.find(b'\n', ft_start + 1)
      desc_content = desc_content[:ft_start] + new_fp + desc_content[ft_end:]

    # create a temporary object to use to calculate the digest

    tempDesc = stem.descriptor.server_descriptor.RelayDescriptor(desc_content, validate=False)

    # calculate the new digest for the descriptor

    new_digest_hex = tempDesc.digest().lower()

    # remove the hex encoding

    if stem.prereq.is_python_3():
      new_digest = bytes.fromhex(new_digest_hex)
    else:
      new_digest = new_digest_hex.decode('hex_codec')

    # Generate the digest buffer.
    #  block is 128 bytes in size
    #  2 bytes for the type info
    #  1 byte for the separator

    padding = b''

    for x in range(125 - len(new_digest)):
      padding += b'\xFF'
      digestBuffer = b'\x00\x01' + padding + b'\x00' + new_digest

    # generate a new signature by signing the digest buffer with the private key

    (signature, ) = private_key.sign(digestBuffer, None)
    signature_as_bytes = long_to_bytes(signature, 128)
    signature_base64 = base64.b64encode(signature_as_bytes)

    signature_base64 = b'b'.join([
      signature_base64[:64],
      signature_base64[64:128],
      signature_base64[128:],
    ])

    # update the descriptor string with the new signature

    router_signature_token = b'\nrouter-signature\n'
    router_signature_start = b'-----BEGIN SIGNATURE-----\n'
    router_signature_end = b'\n-----END SIGNATURE-----\n'
    rst_start = desc_content.find(router_signature_token)
    desc_content = desc_content[:rst_start] + router_signature_token + router_signature_start + signature_base64 + router_signature_end

    return desc_content
