# akita_ddns/reputation.py
import logging
import threading
from typing import Dict

from .storage import PersistentStorage

class ReputationManager:
    def __init__(self, storage: PersistentStorage, config: Dict):
        self.storage = storage
        self._lock = threading.RLock()
        self._rep = self.storage.load_reputation()

    def update_reputation(self, rid: bytes, change: int):
        rid_hex = rid.hex()
        with self._lock:
            self._rep[rid_hex] = self._rep.get(rid_hex, 0) + change
            self.storage.save_reputation(self._rep)

    def get_reputation(self, rid: bytes) -> int:
        return self._rep.get(rid.hex(), 0)

