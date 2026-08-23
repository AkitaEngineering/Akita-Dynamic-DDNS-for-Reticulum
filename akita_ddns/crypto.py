# akita_ddns/crypto.py
import logging
from typing import Optional

import RNS as ret

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
        if (
            getattr(identity, "pub", None) is not None
            and getattr(identity, "sig_pub", None) is not None
        ):
            return identity
    except Exception as e:
        log.debug(f"Failed to load public key: {e}")
    return None


def verify_signature_with_public_key(
    data: bytes, signature: bytes, public_key: bytes
) -> bool:
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
