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
