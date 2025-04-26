# akita_ddns/crypto.py
import reticulum as ret
import logging
from typing import Optional

# Use logger specific to this module
log = logging.getLogger(__name__)

def generate_signature(data: bytes, identity: ret.Identity) -> Optional[bytes]:
    """
    Signs data using the provided Reticulum identity.

    Args:
        data: The bytes to sign.
        identity: The Reticulum identity object to sign with.

    Returns:
        The signature as bytes, or None if signing fails.
    """
    if not isinstance(data, bytes):
        log.error("Invalid data type provided for signing (expected bytes).")
        return None
    if not isinstance(identity, ret.Identity):
        log.error("Invalid identity object provided for signing.")
        return None

    try:
        signature = identity.sign(data)
        # Avoid logging potentially sensitive data content, just log metadata
        log.debug(f"Generated signature (len={len(signature)}) for data (len={len(data)}) with identity {identity.hash.hex()}")
        return signature
    except Exception as e:
        # Log the specific exception for better debugging
        log.error(f"Failed to generate signature with identity {identity.hash.hex()}: {e}", exc_info=True)
        return None

def verify_signature(data: bytes, signature: bytes, identity_hash: bytes) -> bool:
    """
    Verifies a signature against data using the claimed identity hash.

    Args:
        data: The data that was supposedly signed.
        signature: The signature bytes to verify.
        identity_hash: The claimed hash (e.g., public key hash) of the identity
                       that should have created the signature.

    Returns:
        True if the signature is valid for the data and identity hash, False otherwise.
    """
    # Input validation
    if not isinstance(data, bytes):
        log.warning("Invalid data type provided for verification (expected bytes).")
        return False
    if not isinstance(signature, bytes):
        log.warning(f"Invalid signature format provided for verification (expected bytes).")
        return False
    # Check hash type and length rigorously
    if not isinstance(identity_hash, bytes) or len(identity_hash) != ret.Identity.HASHLENGTH // 8:
         log.warning(f"Invalid identity_hash type or length ({len(identity_hash) if isinstance(identity_hash, bytes) else type(identity_hash)}) provided for verification.")
         return False

    try:
        # Recreate a temporary Identity object from the hash to use its verify method
        # This doesn't require the private key.
        verifier_identity = ret.Identity(identity_hash=identity_hash)
        is_valid = verifier_identity.verify(signature=signature, data=data)
        if is_valid:
            log.debug(f"Signature verified successfully for data (len={len(data)}) against identity hash {identity_hash.hex()}")
        else:
            # Log failure clearly, this is important for security
            log.warning(f"Signature verification FAILED for data (len={len(data)}) against identity hash {identity_hash.hex()}")
        return is_valid
    except Exception as e:
        # This might happen if the hash is invalid or other Reticulum errors occur
        log.error(f"Error during signature verification process for hash {identity_hash.hex()}: {e}", exc_info=True)
        return False

