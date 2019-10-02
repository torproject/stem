import base64
import hashlib
import struct

"""
Onion addresses

  onion_address = base32(PUBKEY | CHECKSUM | VERSION) + '.onion'
  CHECKSUM = H('.onion checksum' | PUBKEY | VERSION)[:2]

  - PUBKEY is the 32 bytes ed25519 master pubkey of the hidden service.
  - VERSION is an one byte version field (default value '\x03')
  - '.onion checksum' is a constant string
  - CHECKSUM is truncated to two bytes before inserting it in onion_address
"""


"""
Blinded key stuff

  Now wrt SRVs, if a client is in the time segment between a new time period
  and a new SRV (i.e. the segments drawn with '-') it uses the current SRV,
  else if the client is in a time segment between a new SRV and a new time
  period (i.e. the segments drawn with '='), it uses the previous SRV.
"""

pass

"""
Subcredential:

  subcredential = H('subcredential' | credential | blinded-public-key
  credential = H('credential' | public-identity-key)

Both keys are in bytes
"""


def get_subcredential(public_identity_key, blinded_key):
  cred_bytes_constant = 'credential'.encode()
  subcred_bytes_constant = 'subcredential'.encode()

  credential = hashlib.sha3_256(b'%s%s' % (cred_bytes_constant, public_identity_key)).digest()
  subcredential = hashlib.sha3_256(b'%s%s%s' % (subcred_bytes_constant, credential, blinded_key)).digest()

  return subcredential


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
    STRING_CONSTANT = 'hsdir-superencrypted-data'

  2.5.2.1. Second layer encryption keys
    SECRET_DATA = blinded-public-key | descriptor_cookie
    STRING_CONSTANT = 'hsdir-encrypted-data'
"""

SALT_LEN = 16
MAC_LEN = 32

S_KEY_LEN = 32
S_IV_LEN = 16
MAC_KEY_LEN = 32


def _ciphertext_mac_is_valid(key, salt, ciphertext, mac):
  """
  Instantiate MAC(key=k, message=m) with H(k_len | k | m), where k_len is
  htonll(len(k)).

  XXX spec:   H(mac_key_len | mac_key | salt_len | salt | encrypted)
  """

  # Construct our own MAC first
  key_len = struct.pack('>Q', len(key))
  salt_len = struct.pack('>Q', len(salt))

  my_mac_body = b'%s%s%s%s%s' % (key_len, key, salt_len, salt, ciphertext)
  my_mac = hashlib.sha3_256(my_mac_body).digest()

  # Compare the two MACs
  return my_mac == mac


def _decrypt_descriptor_layer(ciphertext_blob_b64, revision_counter, public_identity_key, subcredential, secret_data, string_constant):
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  from cryptography.hazmat.backends import default_backend

  # decode the thing
  ciphertext_blob = base64.b64decode(ciphertext_blob_b64)

  if (len(ciphertext_blob) < SALT_LEN + MAC_LEN):
    raise ValueError('bad encrypted blob')

  salt = ciphertext_blob[:16]
  ciphertext = ciphertext_blob[16:-32]
  mac = ciphertext_blob[-32:]

  # INT_8(revision_counter)
  rev_counter_int_8 = struct.pack('>Q', revision_counter)
  secret_input = b'%s%s%s' % (secret_data, subcredential, rev_counter_int_8)
  secret_input = secret_input

  kdf = hashlib.shake_256(b'%s%s%s' % (secret_input, salt, string_constant))
  keys = kdf.digest(S_KEY_LEN + S_IV_LEN + MAC_KEY_LEN)

  secret_key = keys[:S_KEY_LEN]
  secret_iv = keys[S_KEY_LEN:S_KEY_LEN + S_IV_LEN]
  mac_key = keys[S_KEY_LEN + S_IV_LEN:]

  # Now time to decrypt descriptor
  cipher = Cipher(algorithms.AES(secret_key), modes.CTR(secret_iv), default_backend())
  decryptor = cipher.decryptor()
  decrypted = decryptor.update(ciphertext) + decryptor.finalize()

  # validate mac (the mac validates the two fields before the mac)
  if not _ciphertext_mac_is_valid(mac_key, salt, ciphertext, mac):
    raise ValueError('Bad MAC!!!')

  return decrypted


def decrypt_outter_layer(superencrypted_blob_b64, revision_counter, public_identity_key, blinded_key, subcredential):
  secret_data = blinded_key
  string_constant = b'hsdir-superencrypted-data'

  # XXX Remove the BEGIN MESSSAGE around the thing
  superencrypted_blob_b64_lines = superencrypted_blob_b64.split('\n')
  superencrypted_blob_b64 = ''.join(superencrypted_blob_b64_lines[1:-1])

  return _decrypt_descriptor_layer(superencrypted_blob_b64, revision_counter, public_identity_key, subcredential, secret_data, string_constant)


def decrypt_inner_layer(encrypted_blob_b64, revision_counter, public_identity_key, blinded_key, subcredential):
  secret_data = blinded_key
  string_constant = b'hsdir-encrypted-data'

  return _decrypt_descriptor_layer(encrypted_blob_b64, revision_counter, public_identity_key, subcredential, secret_data, string_constant)


def parse_superencrypted_plaintext(outter_layer_plaintext):
  """Super hacky function to parse the superencrypted plaintext. This will need to be replaced by proper stem code."""

  START_CONSTANT = b'-----BEGIN MESSAGE-----\n'
  END_CONSTANT = b'\n-----END MESSAGE-----'

  start = outter_layer_plaintext.find(START_CONSTANT)
  end = outter_layer_plaintext.find(END_CONSTANT)

  start = start + len(START_CONSTANT)

  return outter_layer_plaintext[start:end]
