# akita_ddns/namespace.py
import logging
import threading
from typing import Dict, Optional, Any

from .storage import PersistentStorage
from .crypto import verify_signature

# Use logger specific to this module
log = logging.getLogger(__name__)

class NamespaceManager:
    """Manages namespace creation and ownership, with persistence."""

    def __init__(self, storage_handler: PersistentStorage, config: Dict[str, Any]):
        self.storage = storage_handler
        self.config = config
        # {namespace_name: owner_identity_hash_hex}
        self._owners: Dict[str, str] = {}
        self._lock = threading.RLock() # Protects access to _owners
        self._load_initial_state() # Load state during initialization

    def _load_initial_state(self):
         """Loads the namespace owners from the persistent storage."""
         with self._lock:
              self._owners = self.storage.load_namespaces()
              log.info(f"Initial namespace owners loaded: {len(self._owners)} namespaces.")

    def create_namespace(self, namespace: str, owner_hash: bytes, signature: bytes) -> bool:
        """
        Processes a namespace creation request, verifying the signature, checking for conflicts,
        adding the owner, and persisting the change.

        Args:
            namespace: The name of the namespace to create.
            owner_hash: The identity hash of the intended owner.
            signature: The signature proving ownership, created by signing the creation request.

        Returns:
            True if the namespace was successfully created or already existed with the same owner,
            False otherwise (e.g., signature failure, conflict).
        """
        # Input validation
        if not isinstance(namespace, str) or not namespace.strip():
             log.warning("Attempted to create namespace with empty or invalid name.")
             return False
        namespace = namespace.strip() # Use stripped version
        if '.' in namespace: # Prevent ambiguity with name parsing
             log.warning(f"Attempted to create namespace '{namespace}' containing prohibited character '.'.")
             return False
        if not isinstance(owner_hash, bytes):
             log.warning(f"Invalid owner_hash type for namespace '{namespace}'.")
             return False
        if not isinstance(signature, bytes):
             log.warning(f"Invalid signature type for namespace '{namespace}'.")
             return False

        owner_hash_hex = owner_hash.hex()
        log.info(f"Processing namespace creation request for '{namespace}' by owner {owner_hash_hex}")

        # 1. Verify Signature
        # The data signed should be consistent with what send_namespace_create_request sends
        data_to_verify = f"NAMESPACE_CREATE:{namespace}:{owner_hash_hex}".encode("utf-8")
        if not verify_signature(data_to_verify, signature, owner_hash):
            log.warning(f"Namespace creation signature verification failed for '{namespace}' attempt by {owner_hash_hex}.")
            # TODO: Penalize reputation of sender if possible
            return False

        # 2. Check for Conflicts and Add/Verify Owner
        with self._lock:
            existing_owner = self._owners.get(namespace)
            if existing_owner:
                if existing_owner == owner_hash_hex:
                    log.debug(f"Namespace '{namespace}' already exists with owner {owner_hash_hex}. Request successful (no change).")
                    return True # Already exists with the same owner, treat as success
                else:
                    log.warning(f"Conflicting namespace create request for '{namespace}'. Current owner: {existing_owner}, Request owner: {owner_hash_hex}. Request denied.")
                    return False # Conflict with different owner
            else:
                # Add new namespace owner
                self._owners[namespace] = owner_hash_hex
                log.info(f"Namespace '{namespace}' created and assigned to owner {owner_hash_hex}")
                # Persist the change immediately
                self.storage.save_namespaces(self._owners) # Pass internal dict
                return True

    def is_authorized(self, namespace: str, potential_owner_hash: bytes) -> bool:
        """
        Checks if a given identity hash is the owner of a specific namespace.
        If the namespace doesn't exist in the ownership records, authorization is granted (unowned).

        Args:
            namespace: The namespace name.
            potential_owner_hash: The identity hash to check for ownership.

        Returns:
            True if authorized (owner matches or namespace is unowned), False otherwise.
        """
        if not isinstance(potential_owner_hash, bytes):
             log.warning(f"Invalid potential_owner_hash type provided for namespace '{namespace}' authorization check.")
             return False # Cannot authorize invalid hash type

        potential_owner_hex = potential_owner_hash.hex()
        with self._lock:
            owner = self._owners.get(namespace) # Returns None if namespace not in dict
            if owner is None:
                # Namespace doesn't exist in our ownership records, therefore it's unowned.
                log.debug(f"Namespace '{namespace}' has no registered owner. Authorization granted to {potential_owner_hex}.")
                return True
            else:
                # Namespace exists, check if the potential owner matches the recorded owner.
                authorized = (owner == potential_owner_hex)
                if authorized:
                     log.debug(f"Authorization granted for owned namespace '{namespace}' to owner {potential_owner_hex}.")
                else:
                     log.warning(f"Authorization denied for owned namespace '{namespace}'. Requester {potential_owner_hex} is not owner {owner}.")
                return authorized

    def get_owners(self) -> Dict[str, str]:
        """Returns a copy of the current namespace owners mapping."""
        with self._lock:
            return self._owners.copy()

