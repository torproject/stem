# Copyright 2017-2019, Damian Johnson and The Tor Project
# See LICENSE for licensing information

"""
Parsing for `Tor Ed25519 certificates
<https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt>`_, which are
used to for a variety of purposes...

  * validating the key used to sign server descriptors
  * validating the key used to sign hidden service v3 descriptors
  * signing and encrypting hidden service v3 indroductory points

.. versionadded:: 1.6.0

**Module Overview:**

::

  Ed25519Certificate - Ed25519 signing key certificate
    | +- Ed25519CertificateV1 - version 1 Ed25519 certificate
    |      |- is_expired - checks if certificate is presently expired
    |      |- signing_key - certificate signing key
    |      +- validate - validates a descriptor's signature
    |
    |- from_base64 - decodes base64 encoded certificate data
    +- to_base64 - encodes base64 encoded certificate data

  Ed25519Extension - extension included within an Ed25519Certificate

.. data:: CertType (enum)

  Purpose of Ed25519 certificate. For more information see...

    * `cert-spec.txt <https://gitweb.torproject.org/torspec.git/tree/cert-spec.txt>`_ section A.1
    * `rend-spec-v3.txt <https://gitweb.torproject.org/torspec.git/tree/rend-spec-v3.txt>`_ appendix E

  .. deprecated:: 1.8.0
     Replaced with :data:`stem.client.datatype.CertType`

  ========================  ===========
  CertType                  Description
  ========================  ===========
  **SIGNING**               signing key with an identity key
  **LINK_CERT**             TLS link certificate signed with ed25519 signing key
  **AUTH**                  authentication key signed with ed25519 signing key
  **HS_V3_DESC_SIGNING**    hidden service v3 short-term descriptor signing key
  **HS_V3_INTRO_AUTH**      hidden service v3 introductory point authentication key
  **HS_V3_INTRO_ENCRYPT**   hidden service v3 introductory point encryption key
  ========================  ===========

.. data:: ExtensionType (enum)

  Recognized exception types.

  ====================  ===========
  ExtensionType         Description
  ====================  ===========
  **HAS_SIGNING_KEY**   includes key used to sign the certificate
  ====================  ===========

.. data:: ExtensionFlag (enum)

  Flags that can be assigned to Ed25519 certificate extensions.

  ======================  ===========
  ExtensionFlag           Description
  ======================  ===========
  **AFFECTS_VALIDATION**  extension affects whether the certificate is valid
  **UNKNOWN**             extension includes flags not yet recognized by stem
  ======================  ===========
"""

import base64
import binascii
import collections
import datetime
import hashlib
import re

import stem.descriptor.hidden_service
import stem.descriptor.server_descriptor
import stem.prereq
import stem.util.enum
import stem.util.str_tools

from stem.client.datatype import Size

# TODO: Importing under an alternate name until we can deprecate our redundant
# CertType enum in Stem 2.x.

from stem.client.datatype import CertType as ClientCertType

ED25519_HEADER_LENGTH = 40
ED25519_SIGNATURE_LENGTH = 64

CertType = stem.util.enum.UppercaseEnum(
  'SIGNING',
  'LINK_CERT',
  'AUTH',
  'HS_V3_DESC_SIGNING',
  'HS_V3_INTRO_AUTH',
  'HS_V3_INTRO_ENCRYPT',
)

ExtensionType = stem.util.enum.Enum(('HAS_SIGNING_KEY', 4),)
ExtensionFlag = stem.util.enum.UppercaseEnum('AFFECTS_VALIDATION', 'UNKNOWN')


class Ed25519Extension(collections.namedtuple('Ed25519Extension', ['type', 'flags', 'flag_int', 'data'])):
  """
  Extension within an Ed25519 certificate.

  :var int type: extension type
  :var list flags: extension attribute flags
  :var int flag_int: integer encoding of the extension attribute flags
  :var bytes data: data the extension concerns
  """


class Ed25519Certificate(object):
  """
  Base class for an Ed25519 certificate.

  :var int version: certificate format version
  :var unicode encoded: base64 encoded ed25519 certificate
  """

  def __init__(self, version):
    self.version = version
    self.encoded = None  # TODO: remove in stem 2.x

  @staticmethod
  def from_base64(content):
    """
    Parses the given base64 encoded data as an Ed25519 certificate.

    :param str content: base64 encoded certificate

    :returns: :class:`~stem.descriptor.certificate.Ed25519Certificate` subclsss
      for the given certificate

    :raises: **ValueError** if content is malformed
    """

    content = stem.util.str_tools._to_unicode(content)

    if content.startswith('-----BEGIN ED25519 CERT-----\n') and content.endswith('\n-----END ED25519 CERT-----'):
      content = content[29:-27]

    version = stem.util.str_tools._to_int(Ed25519Certificate._b64_decode(content)[0:1])

    if version == 1:
      return Ed25519CertificateV1.from_base64(content)
    else:
      raise ValueError('Ed25519 certificate is version %i. Parser presently only supports version 1.' % version)

  def to_base64(self, pem = False):
    """
    Base64 encoded certificate data.

    :param bool pem: include `PEM header/footer
      <https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail>`_, for more
      information see `RFC 7468 <https://tools.ietf.org/html/rfc7468>`_

    :returns: **bytes** for our encoded certificate representation
    """

    raise NotImplementedError('Certificate encoding has not been implemented for %s' % type(self).__name__)

  @staticmethod
  def _from_descriptor(keyword, attribute):
    def _parse(descriptor, entries):
      value, block_type, block_contents = entries[keyword][0]

      if not block_contents or block_type != 'ED25519 CERT':
        raise ValueError("'%s' should be followed by a ED25519 CERT block, but was a %s" % (keyword, block_type))

      setattr(descriptor, attribute, Ed25519Certificate.from_base64(block_contents))

    return _parse

  @staticmethod
  def _b64_decode(content):
    try:
      decoded = base64.b64decode(content)

      if not decoded:
        raise TypeError('empty')

      return decoded
    except (TypeError, binascii.Error) as exc:
      raise ValueError("Ed25519 certificate wasn't propoerly base64 encoded (%s):\n%s" % (exc, content))

  def __str__(self):
    return self.to_base64(pem = True)

  @staticmethod
  def parse(content):
    return Ed25519Certificate.from_base64(content)  # TODO: drop this alias in stem 2.x


class Ed25519CertificateV1(Ed25519Certificate):
  """
  Version 1 Ed25519 certificate, which are used for signing tor server
  descriptors.

  :var stem.client.datatype.CertType type: certificate purpose
  :var int type_int: integer value of the certificate purpose
  :var datetime expiration: expiration of the certificate
  :var int key_type: format of the key
  :var bytes key: key content
  :var list extensions: :class:`~stem.descriptor.certificate.Ed25519Extension` in this certificate
  :var bytes signature: certificate signature
  """

  def __init__(self, type_int, expiration, key_type, key, extensions, signature):
    super(Ed25519CertificateV1, self).__init__(1)

    self.type, self.type_int = ClientCertType.get(type_int)
    self.expiration = expiration
    self.key_type = key_type
    self.key = key
    self.extensions = extensions
    self.signature = signature

  def to_base64(self, pem = False):
    if pem:
      return '-----BEGIN ED25519 CERT-----\n%s\n-----END ED25519 CERT-----' % self.encoded
    else:
      return self.encoded

  @staticmethod
  def from_base64(content):
    """
    Parses the given base64 encoded data as a version 1 Ed25519 certificate.

    :param str content: base64 encoded certificate

    :returns: :class:`~stem.descriptor.certificate.Ed25519CertificateV1` for
      this content

    :raises: **ValueError** if certificate is malformed
    """

    decoded = Ed25519Certificate._b64_decode(content)

    if len(decoded) < ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH:
      raise ValueError('Ed25519 certificate was %i bytes, but should be at least %i' % (len(decoded), ED25519_HEADER_LENGTH + ED25519_SIGNATURE_LENGTH))

    type_enum, type_int = ClientCertType.get(stem.util.str_tools._to_int(decoded[1:2]))

    if type_enum in (ClientCertType.LINK, ClientCertType.IDENTITY, ClientCertType.AUTHENTICATE):
      raise ValueError('Ed25519 certificate cannot have a type of %i. This is reserved for CERTS cells.' % type_int)
    elif type_enum == ClientCertType.ED25519_IDENTITY:
      raise ValueError('Ed25519 certificate cannot have a type of 7. This is reserved for RSA identity cross-certification.')
    elif type_enum == ClientCertType.UNKNOWN:
      raise ValueError('Ed25519 certificate type %i is unrecognized' % type_int)

    # expiration time is in hours since epoch
    try:
      expiration = datetime.datetime.utcfromtimestamp(stem.util.str_tools._to_int(decoded[2:6]) * 3600)
    except ValueError as exc:
      raise ValueError('Invalid expiration timestamp (%s): %s' % (exc, stem.util.str_tools._to_int(decoded[2:6]) * 3600))

    key_type = stem.util.str_tools._to_int(decoded[6:7])
    key = decoded[7:39]
    signature = decoded[-ED25519_SIGNATURE_LENGTH:]

    extensions = []
    extension_count = stem.util.str_tools._to_int(decoded[39:40])
    remaining_data = decoded[40:-ED25519_SIGNATURE_LENGTH]

    for i in range(extension_count):
      if len(remaining_data) < 4:
        raise ValueError('Ed25519 extension is missing header field data')

      extension_length = stem.util.str_tools._to_int(remaining_data[:2])
      extension_type = stem.util.str_tools._to_int(remaining_data[2:3])
      extension_flags = stem.util.str_tools._to_int(remaining_data[3:4])
      extension_data = remaining_data[4:4 + extension_length]

      if extension_length != len(extension_data):
        raise ValueError("Ed25519 extension is truncated. It should have %i bytes of data but there's only %i." % (extension_length, len(extension_data)))

      flags, remaining_flags = [], extension_flags

      if remaining_flags % 2 == 1:
        flags.append(ExtensionFlag.AFFECTS_VALIDATION)
        remaining_flags -= 1

      if remaining_flags:
        flags.append(ExtensionFlag.UNKNOWN)

      if extension_type == ExtensionType.HAS_SIGNING_KEY and len(extension_data) != 32:
        raise ValueError('Ed25519 HAS_SIGNING_KEY extension must be 32 bytes, but was %i.' % len(extension_data))

      extensions.append(Ed25519Extension(extension_type, flags, extension_flags, extension_data))
      remaining_data = remaining_data[4 + extension_length:]

    if remaining_data:
      raise ValueError('Ed25519 certificate had %i bytes of unused extension data' % len(remaining_data))

    instance = Ed25519CertificateV1(type_int, expiration, key_type, key, extensions, signature)
    instance.encoded = content

    return instance

  def is_expired(self):
    """
    Checks if this certificate is presently expired or not.

    :returns: **True** if the certificate has expired, **False** otherwise
    """

    return datetime.datetime.now() > self.expiration

  def signing_key(self):
    """
    Provides this certificate's signing key.

    .. versionadded:: 1.8.0

    :returns: **bytes** with the first signing key on the certificate, None if
      not present
    """

    for extension in self.extensions:
      if extension.type == ExtensionType.HAS_SIGNING_KEY:
        return extension.data

    return None

  def validate(self, descriptor):
    """
    Validate our descriptor content matches its ed25519 signature. Supported
    descriptor types include...

      * :class:`~stem.descriptor.server_descriptor.RelayDescriptor`
      * :class:`~stem.descriptor.hidden_service.HiddenServiceDescriptorV3`

    :param stem.descriptor.__init__.Descriptor descriptor: descriptor to validate

    :raises:
      * **ValueError** if signing key or descriptor are invalid
      * **TypeError** if descriptor type is unsupported
      * **ImportError** if cryptography module or ed25519 support unavailable
    """

    if not stem.prereq.is_crypto_available(ed25519 = True):
      raise ImportError('Certificate validation requires the cryptography module and ed25519 support')

    if isinstance(descriptor, stem.descriptor.server_descriptor.RelayDescriptor):
      signed_content = hashlib.sha256(Ed25519CertificateV1._signed_content(descriptor)).digest()
      signature = stem.util.str_tools._decode_b64(descriptor.ed25519_signature)

      self._validate_server_desc_signing_key(descriptor)
    elif isinstance(descriptor, stem.descriptor.hidden_service.HiddenServiceDescriptorV3):
      signed_content = Ed25519CertificateV1._signed_content(descriptor)
      signature = stem.util.str_tools._decode_b64(descriptor.signature)
    else:
      raise TypeError('Certificate validation only supported for server and hidden service descriptors, not %s' % type(descriptor).__name__)

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    try:
      key = Ed25519PublicKey.from_public_bytes(self.key)
      key.verify(signature, signed_content)
    except InvalidSignature:
      raise ValueError('Descriptor Ed25519 certificate signature invalid (signature forged or corrupt)')

  @staticmethod
  def _signed_content(descriptor):
    """
    Provides this descriptor's signing constant, appended with the portion of
    the descriptor that's signed.
    """

    if isinstance(descriptor, stem.descriptor.server_descriptor.RelayDescriptor):
      prefix = b'Tor router descriptor signature v1'
      regex = '(.+router-sig-ed25519 )'
    elif isinstance(descriptor, stem.descriptor.hidden_service.HiddenServiceDescriptorV3):
      prefix = b'Tor onion service descriptor sig v3'
      regex = '(.+)signature '
    else:
      raise ValueError('BUG: %s type unexpected' % type(descriptor).__name__)

    match = re.search(regex, descriptor.get_bytes(), re.DOTALL)

    if not match:
      raise ValueError('Malformed descriptor missing signature line')

    return prefix + match.group(1)

  def _validate_server_desc_signing_key(self, descriptor):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature

    if descriptor.ed25519_master_key:
      signing_key = base64.b64decode(stem.util.str_tools._to_bytes(descriptor.ed25519_master_key) + b'=')
    else:
      signing_key = self.signing_key()

    if not signing_key:
      raise ValueError('Server descriptor missing an ed25519 signing key')

    try:
      key = Ed25519PublicKey.from_public_bytes(signing_key)
      key.verify(self.signature, base64.b64decode(stem.util.str_tools._to_bytes(self.encoded))[:-ED25519_SIGNATURE_LENGTH])
    except InvalidSignature:
      raise ValueError('Ed25519KeyCertificate signing key is invalid (signature forged or corrupt)')


class MyED25519Certificate(object):
  """
  This class represents an ed25519 certificate and it's made for encoding it into a string.
  We should merge this class with the one above.
  """
  def __init__(self, cert_type, expiration_date,
               cert_key_type, certified_pub_key,
               signing_priv_key, include_signing_key,
               version=1):
    """
    :var int version
    :var stem.client.datatype.CertType cert_type
    :var int cert_type_int
    :var datetime expiration_date
    :var int cert_key_type
    :var ED25519PublicKey certified_pub_key
    :var ED25519PrivateKey signing_priv_key
    :var bool include_signing_key
    """
    self.version = version
    self.cert_type, self.cert_type_int = ClientCertType.get(cert_type)
    self.expiration_date = expiration_date
    self.cert_key_type = cert_key_type
    self.certified_pub_key = certified_pub_key

    self.signing_priv_key = signing_priv_key
    self.signing_pub_key = signing_priv_key.public_key()

    self.include_signing_key = include_signing_key
    # XXX validate params

  def _get_certificate_signature(self, msg_body):
    return self.signing_priv_key.sign(msg_body)

  def _get_cert_extensions_bytes(self):
    """
    Build the cert extensions part of the certificate
    """

    from cryptography.hazmat.primitives import serialization
    n_extensions = 0

    # If we need to include the signing key, let's create the extension body
    #         ExtLength [2 bytes]
    #         ExtType   [1 byte]
    #         ExtFlags  [1 byte]
    #         ExtData   [ExtLength bytes]
    if self.include_signing_key:
      n_extensions += 1

      signing_pubkey_bytes = self.signing_pub_key.public_bytes(encoding=serialization.Encoding.Raw,
                                                               format=serialization.PublicFormat.Raw)

      ext_length = len(signing_pubkey_bytes)
      ext_type = 4
      ext_flags = 0
      ext_data = signing_pubkey_bytes

    # Now build the actual byte representation of any extensions
    ext_obj = bytearray()
    ext_obj += Size.CHAR.pack(n_extensions)

    if self.include_signing_key:
      ext_obj += Size.SHORT.pack(ext_length)
      ext_obj += Size.CHAR.pack(ext_type)
      ext_obj += Size.CHAR.pack(ext_flags)
      ext_obj += ext_data

    return bytes(ext_obj)

  def encode(self):
    """Return a bytes representation of this certificate."""
    from cryptography.hazmat.primitives import serialization
    obj = bytearray()

    obj += Size.CHAR.pack(self.version)
    obj += Size.CHAR.pack(self.cert_type_int)

    # Encode EXPIRATION_DATE
    expiration_seconds_since_epoch = stem.util.datetime_to_unix(self.expiration_date)
    expiration_hours_since_epoch = int(expiration_seconds_since_epoch) // 3600
    obj += Size.LONG.pack(expiration_hours_since_epoch)

    # Encode CERT_KEY_TYPE
    obj += Size.CHAR.pack(self.cert_key_type)

    # Encode CERTIFIED_KEY
    certified_pub_key_bytes = self.certified_pub_key.public_bytes(encoding = serialization.Encoding.Raw, format = serialization.PublicFormat.Raw)
    assert(len(certified_pub_key_bytes) == 32)
    obj += certified_pub_key_bytes

    # Encode N_EXTENSIONS and EXTENSIONS
    obj += self._get_cert_extensions_bytes()

    # Do the signature on the body we have so far
    obj += self._get_certificate_signature(bytes(obj))

    return bytes(obj)

  def encode_for_descriptor(self):
    cert_bytes = self.encode()
    cert_b64 = base64.b64encode(cert_bytes)
    cert_b64 = b'\n'.join(stem.util.str_tools._split_by_length(cert_b64, 64))
    return b'-----BEGIN ED25519 CERT-----\n%s\n-----END ED25519 CERT-----' % cert_b64
