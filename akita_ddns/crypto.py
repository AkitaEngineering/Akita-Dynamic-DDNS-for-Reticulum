# akita_ddns/crypto.py
import reticulum as ret
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
    if not isinstance(identity_hash, bytes) or len(identity_hash) != ret.Identity.HASHLENGTH // 8:
         return False

    try:
        # Creates an identity handle. Note: Reticulum must know the Public Key 
        # (via previous Announcement or storage) to verify.
        verifier_identity = ret.Identity(identity_hash=identity_hash)
        return verifier_identity.verify(signature=signature, data=data)
    except Exception as e:
        log.debug(f"Signature verification failed: {e}")
        return False
