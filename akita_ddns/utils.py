# akita_ddns/utils.py
import logging
import os
import re
import threading
import time
from typing import Optional, Tuple

import msgpack
import RNS as ret

log = logging.getLogger(__name__)

LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_-]{0,62})$")
HASH_BYTES = int(getattr(ret.Identity, "TRUNCATED_HASHLENGTH", 128)) // 8


class RateLimiter:
    """Thread-safe token bucket rate limiter."""

    def __init__(self, rate: float, capacity: Optional[float] = None):
        if rate <= 0:
            raise ValueError("Rate must be positive")
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


def build_registration_payload(
    ns: str, name: str, rid_hex: str, ttl: int, timestamp: Optional[int] = None
) -> bytes:
    """Builds the signed registration payload used on the wire."""
    rid = bytes.fromhex(rid_hex)
    fields = [1, "REGISTER", ns, name, rid, int(ttl)]
    if timestamp is not None:
        fields.append(int(timestamp))
    return msgpack.packb(fields, use_bin_type=True, strict_types=True)


def build_namespace_create_payload(ns: str, owner: bytes) -> bytes:
    return msgpack.packb(
        [1, "NAMESPACE_CREATE", ns, owner], use_bin_type=True, strict_types=True
    )


def build_namespace_transfer_payload(
    ns: str, new_owner: bytes, sequence: int, timestamp: int, transfer_id: bytes
) -> bytes:
    return msgpack.packb(
        [
            1,
            "NAMESPACE_TRANSFER",
            ns,
            new_owner,
            int(sequence),
            int(timestamp),
            transfer_id,
        ],
        use_bin_type=True,
        strict_types=True,
    )


def validate_label(value: str, field: str) -> str:
    if not isinstance(value, str) or not LABEL_RE.fullmatch(value):
        raise ValueError(
            f"{field} must be 1-63 ASCII letters, digits, underscores, or hyphens "
            "and must start with a letter or digit"
        )
    return value


def validate_hash(value: bytes, field: str = "hash") -> bytes:
    if not isinstance(value, bytes) or len(value) != HASH_BYTES:
        raise ValueError(f"{field} must be exactly {HASH_BYTES} bytes")
    return value


def validate_public_key(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise ValueError("public key must be exactly 64 bytes")
    return value


def validate_signature(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 64:
        raise ValueError("signature must be exactly 64 bytes")
    return value


def validate_registration_times(
    timestamp: int,
    ttl: int,
    *,
    now: Optional[int] = None,
    max_ttl: int,
    max_clock_skew: int,
) -> Tuple[int, int]:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ValueError("timestamp must be an integer")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= max_ttl:
        raise ValueError(f"ttl must be between 1 and {max_ttl} seconds")
    current = int(time.time()) if now is None else int(now)
    if timestamp > current + max_clock_skew:
        raise ValueError("timestamp is too far in the future")
    if timestamp + ttl <= current:
        raise ValueError("registration is already expired")
    return timestamp, ttl


def parse_name(full_name: str, default_namespace: str) -> Tuple[str, str]:
    """Splits a name into (name, namespace)."""
    if not isinstance(full_name, str) or not full_name.strip():
        raise ValueError("Name cannot be empty.")
    if not default_namespace or not default_namespace.strip():
        raise ValueError("Invalid default namespace.")

    full_name = full_name.strip()
    parts = full_name.split(".", 1)

    name_part = parts[0].strip()
    validate_label(name_part, "name")

    namespace_part = (
        parts[1].strip()
        if len(parts) > 1 and parts[1].strip()
        else default_namespace.strip()
    )
    validate_label(namespace_part, "namespace")

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
            parent = os.path.dirname(os.path.abspath(identity_path))
            os.makedirs(parent, mode=0o700, exist_ok=True)
            identity.to_file(identity_path)
            try:
                os.chmod(identity_path, 0o600)
            except OSError:
                log.warning(
                    "Could not restrict identity file permissions: %s", identity_path
                )
    return identity
