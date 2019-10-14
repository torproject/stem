import base64
import hashlib
import struct
import os

import stem.descriptor.slow_ed25519
import stem.prereq

from stem.descriptor import ed25519_exts_ref
from stem.descriptor import slow_ed25519

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def pubkeys_are_equal(pubkey1, pubkey2):
  """
  Compare the raw bytes of the two pubkeys and return True if they are the same
  """

  pubkey1_bytes = pubkey1.public_bytes(encoding = serialization.Encoding.Raw, format = serialization.PublicFormat.Raw)
  pubkey2_bytes = pubkey2.public_bytes(encoding = serialization.Encoding.Raw, format = serialization.PublicFormat.Raw)

  return pubkey1_bytes == pubkey2_bytes


"""
HSv3 Key blinding

Expose classes for HSv3 blinded keys which can mimic the hazmat ed25519
public/private key classes, so that we can use them interchangeably in the
certificate module.

- HSv3PublicBlindedKey: represents the public blinded ed25519 key of an onion
  service and should expose a public_bytes() method and a verify() method.

- HSv3PrivateBlindedKey: represents the private part of a blinded ed25519 key
  of an onion service and should expose a public_key() method and a sign() method.
"""


class HSv3PrivateBlindedKey(object):
  def __init__(self, hazmat_private_key, blinding_param):
    secret_seed = hazmat_private_key.private_bytes(encoding = serialization.Encoding.Raw, format = serialization.PrivateFormat.Raw, encryption_algorithm = serialization.NoEncryption())
    assert(len(secret_seed) == 32)

    expanded_identity_priv_key = ed25519_exts_ref.expandSK(secret_seed)
    identity_public_key = slow_ed25519.publickey(secret_seed)

    self.blinded_secret_key = ed25519_exts_ref.blindESK(expanded_identity_priv_key, blinding_param)
    blinded_public_key = ed25519_exts_ref.blindPK(identity_public_key, blinding_param)
    self.blinded_public_key = HSv3PublicBlindedKey(blinded_public_key)

  def public_key(self):
    return self.blinded_public_key

  def sign(self, msg):
    return ed25519_exts_ref.signatureWithESK(msg, self.blinded_secret_key, self.blinded_public_key.public_bytes())


class HSv3PublicBlindedKey(object):
  def __init__(self, public_key):
    self.public_key = public_key

  def public_bytes(self, encoding=None, format=None):
    return self.public_key

  def verify(self, signature, message):
    """
    raises exception if sig not valid
    """

    stem.descriptor.slow_ed25519.checkvalid(signature, message, self.public_key)


"""
subcredential

       subcredential = H("subcredential" | credential | blinded-public-ke
       credential = H("credential" | public-identity-key)
"""


def get_subcredential(public_identity_key, blinded_key):
  cred_bytes_constant = 'credential'.encode()
  subcred_bytes_constant = 'subcredential'.encode()

  credential = hashlib.sha3_256(b'%s%s' % (cred_bytes_constant, public_identity_key)).digest()
  subcredential = hashlib.sha3_256(b'%s%s%s' % (subcred_bytes_constant, credential, blinded_key)).digest()

  return subcredential


"""
Onion address

     onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
     CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]

       - PUBKEY is the 32 bytes ed25519 master pubkey of the hidden service.
       - VERSION is an one byte version field (default value '\x03')
       - ".onion checksum" is a constant string
       - CHECKSUM is truncated to two bytes before inserting it in onion_address
"""

CHECKSUM_CONSTANT = b'.onion checksum'


def encode_onion_address(ed25519_pub_key_bytes):
  """
  Given the public key, return the onion address
  """

  if not stem.prereq._is_sha3_available():
    raise ImportError('Encoding onion addresses requires python 3.6+ or the pysha3 module (https://pypi.org/project/pysha3/)')

  version = 3
  checksum_body = b'%s%s%d' % (CHECKSUM_CONSTANT, ed25519_pub_key_bytes, version)
  checksum = hashlib.sha3_256(checksum_body).digest()[:2]

  onion_address_bytes = b'%s%s%d' % (ed25519_pub_key_bytes, checksum, version)
  onion_address = base64.b32encode(onion_address_bytes) + b'.onion'
  assert(len(onion_address) == 56 + len('.onion'))

  return onion_address.lower()


"""
Basic descriptor logic:

       SALT = 16 bytes from H(random), changes each time we rebuld the
              descriptor even if the content of the descriptor hasn't changed.
              (So that we don't leak whether the intro point list etc. changed)

       secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)

       keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)

       SECRET_KEY = first S_KEY_LEN bytes of keys
       SECRET_IV  = next S_IV_LEN bytes of keys
       MAC_KEY    = last MAC_KEY_LEN bytes of keys


Layer data:

 2.5.1.1. First layer encryption logic
     SECRET_DATA = blinded-public-key
     STRING_CONSTANT = "hsdir-superencrypted-data"

 2.5.2.1. Second layer encryption keys
     SECRET_DATA = blinded-public-key | descriptor_cookie
     STRING_CONSTANT = "hsdir-encrypted-data"
"""

SALT_LEN = 16
MAC_LEN = 32

S_KEY_LEN = 32
S_IV_LEN = 16
MAC_KEY_LEN = 32

"""
Descriptor encryption
"""


def pack(val):
  return struct.pack('>Q', val)


def get_desc_keys(secret_data, string_constant, subcredential, revision_counter, salt):
  """
  secret_input = SECRET_DATA | subcredential | INT_8(revision_counter)

  keys = KDF(secret_input | salt | STRING_CONSTANT, S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)

  SECRET_KEY = first S_KEY_LEN bytes of keys
  SECRET_IV  = next S_IV_LEN bytes of keys
  MAC_KEY    = last MAC_KEY_LEN bytes of keys

  where

  2.5.1.1. First layer encryption logic
    SECRET_DATA = blinded-public-key
    STRING_CONSTANT = "hsdir-superencrypted-data"

  2.5.2.1. Second layer encryption keys
    SECRET_DATA = blinded-public-key | descriptor_cookie
    STRING_CONSTANT = "hsdir-encrypted-data"
  """

  secret_input = b'%s%s%s' % (secret_data, subcredential, pack(revision_counter))

  kdf = hashlib.shake_256(secret_input + salt + string_constant)

  keys = kdf.digest(S_KEY_LEN + S_IV_LEN + MAC_LEN)

  secret_key = keys[:S_KEY_LEN]
  secret_iv = keys[S_KEY_LEN:S_KEY_LEN + S_IV_LEN]
  mac_key = keys[S_KEY_LEN + S_IV_LEN:]

  return secret_key, secret_iv, mac_key


def get_desc_encryption_mac(key, salt, ciphertext):
  mac = hashlib.sha3_256(pack(len(key)) + key + pack(len(salt)) + salt + ciphertext).digest()
  return mac


def _encrypt_descriptor_layer(plaintext, revision_counter, subcredential, secret_data, string_constant):
  """
  Encrypt descriptor layer at 'plaintext'
  """

  salt = os.urandom(16)

  secret_key, secret_iv, mac_key = get_desc_keys(secret_data, string_constant, subcredential, revision_counter, salt)

  # Now time to encrypt descriptor
  cipher = Cipher(algorithms.AES(secret_key), modes.CTR(secret_iv), default_backend())
  encryptor = cipher.encryptor()
  ciphertext = encryptor.update(plaintext) + encryptor.finalize()

  mac = get_desc_encryption_mac(mac_key, salt, ciphertext)

  return salt + ciphertext + mac


def encrypt_inner_layer(plaintext, revision_counter, blinded_key_bytes, subcredential):
  """
  Encrypt the inner layer of the descriptor
  """

  secret_data = blinded_key_bytes
  string_constant = b'hsdir-encrypted-data'

  return _encrypt_descriptor_layer(plaintext, revision_counter, subcredential, secret_data, string_constant)


def ceildiv(a, b):
  """
  Like // division but return the ceiling instead of the floor
  """

  return -(-a // b)


def _get_padding_needed(plaintext_len):
  """
  Get descriptor padding needed for this descriptor layer.
  From the spec:
     Before encryption the plaintext is padded with NUL bytes to the nearest
     multiple of 10k bytes.
  """

  PAD_MULTIPLE_BYTES = 10000

  final_size = ceildiv(plaintext_len, PAD_MULTIPLE_BYTES) * PAD_MULTIPLE_BYTES
  return final_size - plaintext_len


def encrypt_outter_layer(plaintext, revision_counter, blinded_key_bytes, subcredential):
  """
  Encrypt the outer layer of the descriptor
  """

  secret_data = blinded_key_bytes
  string_constant = b'hsdir-superencrypted-data'

  # In the outter layer we first need to pad the plaintext
  padding_bytes_needed = _get_padding_needed(len(plaintext))
  padded_plaintext = plaintext + b'\x00' * padding_bytes_needed

  return _encrypt_descriptor_layer(padded_plaintext, revision_counter, subcredential, secret_data, string_constant)
