# akita_ddns/namespace.py
import logging
import threading
from typing import Dict

from .storage import PersistentStorage
from .crypto import verify_signature, verify_signature_with_public_key, identity_from_public_key

log = logging.getLogger(__name__)

class NamespaceManager:
    def __init__(self, storage: PersistentStorage, config: Dict):
        self.storage = storage
        self._lock = threading.RLock()
        self._owners = self.storage.load_namespaces()

    def create_namespace(self, ns: str, owner: bytes, owner_pubkey: bytes, sig: bytes) -> bool:
        if not ns or '.' in ns: return False
        
        # Verify Sig
        payload = f"NAMESPACE_CREATE:{ns}:{owner.hex()}".encode("utf-8")
        identity = identity_from_public_key(owner_pubkey)
        if not identity or identity.hash != owner:
            return False
        if not verify_signature_with_public_key(payload, sig, owner_pubkey):
            log.warning(f"Invalid signature for namespace {ns}")
            return False

        with self._lock:
            curr = self._owners.get(ns)
            if curr:
                return curr == owner.hex()
            
            self._owners[ns] = owner.hex()
            log.info(f"Created namespace {ns} owner {owner.hex()}")
            self.storage.save_namespaces(self._owners)
            return True

    def is_authorized(self, ns: str, potential_owner: bytes) -> bool:
        with self._lock:
            owner = self._owners.get(ns)
            if not owner: return True # Unowned = authorized for anyone
            return owner == potential_owner.hex()

    def get_owners(self) -> Dict[str, str]:
        with self._lock: return self._owners.copy()
