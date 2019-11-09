from stem.descriptor import slow_ed25519


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


def blindESK(esk, param):
  mult = 2 ** (slow_ed25519.b - 2) + sum(2 ** i * slow_ed25519.bit(param, i) for i in range(3, slow_ed25519.b - 2))
  s = slow_ed25519.decodeint(esk[:32])
  s_prime = (s * mult) % slow_ed25519.l
  k = esk[32:]
  assert(len(k) == 32)
  k_prime = slow_ed25519.H(b'Derive temporary signing key hash input' + k)[:32]
  return slow_ed25519.encodeint(s_prime) + k_prime


def blindPK(pk, param):
  mult = 2 ** (slow_ed25519.b - 2) + sum(2 ** i * slow_ed25519.bit(param, i) for i in range(3, slow_ed25519.b - 2))
  P = slow_ed25519.decodepoint(pk)
  return slow_ed25519.encodepoint(slow_ed25519.scalarmult(P, mult))


def expandSK(sk):
  h = slow_ed25519.H(sk)
  a = 2 ** (slow_ed25519.b - 2) + sum(2 ** i * slow_ed25519.bit(h, i) for i in range(3, slow_ed25519.b - 2))
  k = b''.join([h[i:i + 1] for i in range(slow_ed25519.b // 8, slow_ed25519.b // 4)])
  assert len(k) == 32
  return slow_ed25519.encodeint(a) + k


def signatureWithESK(m, h, pk):
  a = slow_ed25519.decodeint(h[:32])
  r = slow_ed25519.Hint(b''.join([h[i:i + 1] for i in range(slow_ed25519.b // 8, slow_ed25519.b // 4)]) + m)
  R = slow_ed25519.scalarmult(slow_ed25519.B, r)
  S = (r + slow_ed25519.Hint(slow_ed25519.encodepoint(R) + pk + m) * a) % slow_ed25519.l

  return slow_ed25519.encodepoint(R) + slow_ed25519.encodeint(S)


class HSv3PrivateBlindedKey(object):
  def __init__(self, hazmat_private_key, blinding_param):
    from cryptography.hazmat.primitives import serialization

    secret_seed = hazmat_private_key.private_bytes(encoding = serialization.Encoding.Raw, format = serialization.PrivateFormat.Raw, encryption_algorithm = serialization.NoEncryption())
    assert(len(secret_seed) == 32)

    expanded_identity_priv_key = expandSK(secret_seed)
    identity_public_key = slow_ed25519.publickey(secret_seed)

    self.blinded_secret_key = blindESK(expanded_identity_priv_key, blinding_param)
    self.blinded_pubkey = blindPK(identity_public_key, blinding_param)

  def sign(self, msg):
    return signatureWithESK(msg, self.blinded_secret_key, self.blinded_pubkey)


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
