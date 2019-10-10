import base64
import hashlib
import struct
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import stem.descriptor.ed25519_exts_ref as ed25519_exts_ref
import stem.descriptor.slow_ed25519 as slow_ed25519

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
        secret_seed = hazmat_private_key.private_bytes(encoding=serialization.Encoding.Raw,
                                                       format=serialization.PrivateFormat.Raw,
                                                       encryption_algorithm=serialization.NoEncryption())
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
        ext.slow_ed25519.checkvalid(signature, message, self.public_key)

