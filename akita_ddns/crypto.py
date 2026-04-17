# akita_ddns/crypto.py
import RNS as ret
import logging
from typing import Optional

log = logging.getLogger(__name__)

def generate_signature(data: bytes, identity: ret.Identity) -> Optional[bytes]:
    """Signs data using the provided Reticulum identity."""
    if not isinstance(data, bytes) or not isinstance(identity, ret.Identity):
        log.error("Invalid types for signing.")
        return None
    try:
        return identity.sign(data)
    except Exception as e:
        log.error(f"Signature generation failed: {e}")
        return None

def verify_signature(data: bytes, signature: bytes, identity_hash: bytes) -> bool:
    """Verifies a signature against data using the claimed identity hash."""
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        return False
    hash_len_bits = getattr(ret.Identity, "TRUNCATED_HASHLENGTH", None)
    if hash_len_bits is None:
        hash_len_bits = getattr(ret.Identity, "HASHLENGTH", 256)
    if not isinstance(identity_hash, bytes) or len(identity_hash) != int(hash_len_bits) // 8:
         return False

    try:
        # Requires that the public key for the identity hash is known to RNS.
        verifier_identity = ret.Identity.recall(identity_hash, from_identity_hash=True)
        if not verifier_identity:
            return False
        return verifier_identity.validate(signature, data)
    except Exception as e:
        log.debug(f"Signature verification failed: {e}")
        return False

def identity_from_public_key(public_key: bytes) -> Optional[ret.Identity]:
    """Creates an Identity instance from a public key."""
    if not isinstance(public_key, bytes):
        return None
    try:
        try:
            identity = ret.Identity(create_keys=False)
        except TypeError:
            identity = ret.Identity()
        identity.load_public_key(public_key)
        if getattr(identity, "pub", None) is not None and getattr(identity, "sig_pub", None) is not None:
            return identity
    except Exception as e:
        log.debug(f"Failed to load public key: {e}")
    return None

def verify_signature_with_public_key(data: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verifies a signature using a provided public key."""
    if not isinstance(data, bytes) or not isinstance(signature, bytes):
        return False
    identity = identity_from_public_key(public_key)
    if not identity:
        return False
    try:
        return identity.validate(signature, data)
    except Exception as e:
        log.debug(f"Signature verification failed: {e}")
        return False
