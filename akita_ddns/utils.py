# akita_ddns/utils.py
import time
import threading
import logging
from typing import Optional, Tuple

import RNS as ret
import os

log = logging.getLogger(__name__)

class RateLimiter:
    """Thread-safe token bucket rate limiter."""
    def __init__(self, rate: float, capacity: float = None):
        if rate <= 0: raise ValueError("Rate must be positive")
        self.rate = float(rate)
        self.capacity = max(self.rate, float(capacity) if capacity else self.rate)
        self.tokens = self.capacity
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def check(self) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                return True
            return False

def build_registration_payload(ns: str, name: str, rid_hex: str, ttl: int, timestamp: Optional[int] = None) -> bytes:
    """Builds the signed registration payload used on the wire."""
    payload = f"{ns}:{name}:{rid_hex}:{int(ttl)}"
    if timestamp is not None:
        payload = f"{payload}:{int(timestamp)}"
    return payload.encode("utf-8")

def parse_name(full_name: str, default_namespace: str) -> Tuple[str, str]:
    """Splits a name into (name, namespace)."""
    if not isinstance(full_name, str) or not full_name.strip():
        raise ValueError("Name cannot be empty.")
    if not default_namespace or not default_namespace.strip():
         raise ValueError("Invalid default namespace.")

    full_name = full_name.strip()
    parts = full_name.split('.', 1)
    
    name_part = parts[0].strip()
    if not name_part: raise ValueError("Name part cannot be empty.")

    namespace_part = parts[1].strip() if len(parts) > 1 and parts[1].strip() else default_namespace.strip()
    if not namespace_part: raise ValueError("Namespace part cannot be empty.")

    return name_part, namespace_part

def load_or_create_identity(identity_path: str, save: bool = True) -> ret.Identity:
    """Loads an identity from file or creates a new one."""
    if not identity_path:
        raise ValueError("Identity path is required")
    identity = None
    if os.path.exists(identity_path):
        identity = ret.Identity.from_file(identity_path)
    if not identity:
        identity = ret.Identity()
        if save:
            identity.to_file(identity_path)
    return identity
