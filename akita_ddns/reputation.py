# akita_ddns/reputation.py
import threading
from typing import Dict

from .storage import PersistentStorage


class ReputationManager:
    def __init__(self, storage: PersistentStorage, config: Dict):
        self.storage = storage
        self._lock = threading.RLock()
        self._rep = self.storage.load_reputation()

    def update_reputation(self, rid: bytes, change: int) -> bool:
        if (
            not isinstance(rid, bytes)
            or not isinstance(change, int)
            or isinstance(change, bool)
        ):
            raise ValueError("Invalid reputation update")
        rid_hex = rid.hex()
        with self._lock:
            previous = self._rep.get(rid_hex)
            self._rep[rid_hex] = (previous or 0) + change
            if not self.storage.save_reputation(self._rep):
                if previous is None:
                    del self._rep[rid_hex]
                else:
                    self._rep[rid_hex] = previous
                return False
            return True

    def get_reputation(self, rid: bytes) -> int:
        with self._lock:
            return self._rep.get(rid.hex(), 0)

    def snapshot(self) -> Dict[str, int]:
        with self._lock:
            return self._rep.copy()
