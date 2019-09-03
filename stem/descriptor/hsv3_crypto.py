import base64
import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


"""
Onion addresses

     onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
     CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]

       - PUBKEY is the 32 bytes ed25519 master pubkey of the hidden service.
       - VERSION is an one byte version field (default value '\x03')
       - ".onion checksum" is a constant string
       - CHECKSUM is truncated to two bytes before inserting it in onion_address

"""

CHECKSUM_CONSTANT = b".onion checksum"

def decode_address(onion_address_str):
    """
    Parse onion_address_str and return the pubkey.

         onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
         CHECKSUM = H(".onion checksum" | PUBKEY | VERSION)[:2]

    :return: Ed25519PublicKey

    :raises: ValueError
    """
    if (len(onion_address_str) != 56 + len(".onion")):
        raise ValueError("Wrong address length")

    # drop the '.onion'
    onion_address = onion_address_str[:56]

    # base32 decode the addr (convert to uppercase since that's what python expects)
    onion_address = base64.b32decode(onion_address.upper())
    assert(len(onion_address) == 35)

    # extract pieces of information
    pubkey = onion_address[:32]
    checksum = onion_address[32:34]
    version = onion_address[34]

    # Do checksum validation
    my_checksum_body = b"%s%s%s" % (CHECKSUM_CONSTANT, pubkey, bytes([version]))
    my_checksum = hashlib.sha3_256(my_checksum_body).digest()

    if (checksum != my_checksum[:2]):
        raise ValueError("Bad checksum")

    return Ed25519PublicKey.from_public_bytes(pubkey)
