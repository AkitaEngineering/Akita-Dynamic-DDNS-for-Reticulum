"""Thread-safe persistent registry and resolution cache."""

import copy
import logging
import os
import tempfile
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .crypto import identity_from_public_key, verify_signature_with_public_key
from .utils import (
    build_registration_payload,
    validate_hash,
    validate_label,
    validate_public_key,
    validate_registration_times,
    validate_signature,
)

log = logging.getLogger(__name__)

# (RID bytes; empty for a tombstone, signed timestamp, signature, expiry, public key)
RegistryEntry = Tuple[bytes, int, bytes, int, bytes]
CacheEntry = Tuple[RegistryEntry, float]


class StorageError(RuntimeError):
    """Raised when configured persistent state cannot be read safely."""


class PersistentStorage:
    """Save and load state with bounded reads and crash-durable atomic writes."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._file_lock = threading.Lock()
        self.max_file_bytes = int(config.get("max_state_file_bytes", 16 * 1024 * 1024))

    def _save_yaml(self, data: Dict[str, Any], file_path: Optional[str]) -> bool:
        if not self.config.get("persist_state") or not file_path:
            return True

        directory = os.path.dirname(os.path.abspath(file_path))
        with self._file_lock:
            temp_path: Optional[str] = None
            try:
                os.makedirs(directory, mode=0o700, exist_ok=True)
                descriptor, temp_path = tempfile.mkstemp(
                    prefix=".akita-", dir=directory
                )
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    yaml.safe_dump(
                        data, handle, default_flow_style=False, sort_keys=True
                    )
                    handle.flush()
                    os.fsync(handle.fileno())
                    if os.fstat(handle.fileno()).st_size > self.max_file_bytes:
                        raise StorageError(f"state exceeds {self.max_file_bytes} bytes")
                os.replace(temp_path, file_path)
                temp_path = None
                try:
                    directory_fd = os.open(directory, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError:
                    # Some filesystems do not support syncing directory handles.
                    pass
                return True
            except (OSError, StorageError, yaml.YAMLError) as exc:
                log.error("Failed to save %s: %s", file_path, exc)
                return False
            finally:
                if temp_path:
                    try:
                        os.unlink(temp_path)
                    except FileNotFoundError:
                        pass

    def _load_yaml(self, file_path: Optional[str]) -> Dict[str, Any]:
        if (
            not self.config.get("persist_state")
            or not file_path
            or not os.path.exists(file_path)
        ):
            return {}
        with self._file_lock:
            try:
                if os.path.islink(file_path) or not os.path.isfile(file_path):
                    raise ValueError("state path is not a regular file")
                if os.path.getsize(file_path) > self.max_file_bytes:
                    raise ValueError(f"state file exceeds {self.max_file_bytes} bytes")
                with open(file_path, "r", encoding="utf-8") as handle:
                    data = yaml.safe_load(handle)
                if data is None:
                    return {}
                if not isinstance(data, dict):
                    raise ValueError("state root is not a mapping")
                return data
            except (OSError, ValueError, yaml.YAMLError) as exc:
                raise StorageError(f"Failed to load {file_path}: {exc}") from exc

    def save_registry(self, registry_data: Dict[str, Dict[str, RegistryEntry]]) -> bool:
        if not self.config.get("registry_file_path"):
            return True
        now = time.time()
        serializable: Dict[str, Dict[str, List[Any]]] = {}
        for namespace, names in registry_data.items():
            saved_names = {}
            for name, entry in names.items():
                if now < entry[3]:
                    saved_names[name] = [
                        entry[0].hex(),
                        entry[1],
                        entry[2].hex(),
                        entry[3],
                        entry[4].hex(),
                    ]
            if saved_names:
                serializable[namespace] = saved_names
        return self._save_yaml(serializable, self.config["registry_file_path"])

    def load_registry(self) -> Dict[str, Dict[str, RegistryEntry]]:
        raw = self._load_yaml(self.config.get("registry_file_path"))
        registry: Dict[str, Dict[str, RegistryEntry]] = {}
        now = int(time.time())
        max_ttl = int(self.config.get("max_registration_ttl", 604800))
        max_skew = int(self.config.get("max_clock_skew", 300))
        max_entries = int(self.config.get("max_registry_size", 10000))
        entry_count = 0
        for namespace, names in raw.items():
            if entry_count >= max_entries:
                log.warning(
                    "Persisted registry exceeds configured capacity; truncating"
                )
                break
            if not isinstance(names, dict):
                continue
            try:
                validate_label(namespace, "namespace")
            except ValueError:
                continue
            valid_names: Dict[str, RegistryEntry] = {}
            for name, serialized in names.items():
                if entry_count >= max_entries:
                    log.warning(
                        "Persisted registry exceeds configured capacity; truncating"
                    )
                    break
                try:
                    validate_label(name, "name")
                    if not isinstance(serialized, list) or len(serialized) != 5:
                        raise ValueError("invalid registry entry")
                    rid = bytes.fromhex(serialized[0])
                    if rid:
                        validate_hash(rid, "RID")
                    timestamp = int(serialized[1])
                    signature = bytes.fromhex(serialized[2])
                    expiration = int(serialized[3])
                    public_key = bytes.fromhex(serialized[4])
                    validate_signature(signature)
                    validate_public_key(public_key)
                    ttl = expiration - timestamp
                    validate_registration_times(
                        timestamp,
                        ttl,
                        now=now,
                        max_ttl=max_ttl,
                        max_clock_skew=max_skew,
                    )
                    payload = build_registration_payload(
                        namespace, name, rid.hex(), ttl, timestamp
                    )
                    if not verify_signature_with_public_key(
                        payload, signature, public_key
                    ):
                        raise ValueError("invalid signature")
                    valid_names[name] = (
                        rid,
                        timestamp,
                        signature,
                        expiration,
                        public_key,
                    )
                    entry_count += 1
                except (TypeError, ValueError, OverflowError):
                    log.warning(
                        "Ignoring invalid persisted registry entry %r@%r",
                        name,
                        namespace,
                    )
            if valid_names:
                registry[namespace] = valid_names
        return registry

    def save_namespaces(self, records: Dict[str, Any]) -> bool:
        return self._save_yaml(
            copy.deepcopy(records), self.config.get("namespace_owners_file_path")
        )

    def load_namespaces(self) -> Dict[str, Any]:
        return self._load_yaml(self.config.get("namespace_owners_file_path"))

    def save_reputation(self, reputation: Dict[str, int]) -> bool:
        return self._save_yaml(
            reputation.copy(), self.config.get("reputation_file_path")
        )

    def load_reputation(self) -> Dict[str, int]:
        raw = self._load_yaml(self.config.get("reputation_file_path"))
        result = {}
        for key, value in raw.items():
            if (
                isinstance(key, str)
                and isinstance(value, int)
                and not isinstance(value, bool)
            ):
                result[key] = value
        return result


class Registry:
    def __init__(self, storage: PersistentStorage, config: Dict[str, Any]):
        self.storage = storage
        self.config = config
        self.max_size = int(config.get("max_registry_size", 10000))
        self.max_ttl = int(config.get("max_registration_ttl", 604800))
        self.max_clock_skew = int(config.get("max_clock_skew", 300))
        self._lock = threading.RLock()
        self._registry = self.storage.load_registry()

    @staticmethod
    def _wins(candidate: RegistryEntry, current: RegistryEntry) -> bool:
        if candidate[1] != current[1]:
            return candidate[1] > current[1]
        # A deterministic tie-break prevents peers diverging on two updates in one second.
        return (candidate[3], candidate[0], candidate[4], candidate[2]) > (
            current[3],
            current[0],
            current[4],
            current[2],
        )

    def _entry_count(self) -> int:
        return sum(len(names) for names in self._registry.values())

    def register(
        self,
        ns: str,
        name: str,
        rid: bytes,
        ts: int,
        sig: bytes,
        exp: int,
        public_key: bytes,
    ) -> bool:
        validate_label(ns, "namespace")
        validate_label(name, "name")
        if not isinstance(rid, bytes):
            raise ValueError("RID must be bytes")
        if rid:
            validate_hash(rid, "RID")
        validate_signature(sig)
        validate_public_key(public_key)
        if isinstance(exp, bool) or not isinstance(exp, int):
            raise ValueError("expiration must be an integer")
        ttl = int(exp) - int(ts)
        validate_registration_times(
            ts,
            ttl,
            max_ttl=self.max_ttl,
            max_clock_skew=self.max_clock_skew,
        )
        payload = build_registration_payload(ns, name, rid.hex(), ttl, ts)
        if not verify_signature_with_public_key(payload, sig, public_key):
            return False

        entry: RegistryEntry = (rid, int(ts), sig, int(exp), public_key)
        with self._lock:
            current = self._registry.get(ns, {}).get(name)
            if current == entry:
                return False
            if current and not self._wins(entry, current):
                return False
            if current is None and self._entry_count() >= self.max_size:
                self.run_ttl_check()
                if self._entry_count() >= self.max_size:
                    log.warning("Registry capacity reached; refusing new entry")
                    return False
            self._registry.setdefault(ns, {})[name] = entry
            if not self.storage.save_registry(self._registry):
                if current is None:
                    del self._registry[ns][name]
                    if not self._registry[ns]:
                        del self._registry[ns]
                else:
                    self._registry[ns][name] = current
                return False
        if rid:
            log.info("Registered %s@%s -> %s", name, ns, rid.hex())
        else:
            log.info("Revoked %s@%s", name, ns)
        return True

    def resolve(self, ns: str, name: str) -> Optional[RegistryEntry]:
        validate_label(ns, "namespace")
        validate_label(name, "name")
        with self._lock:
            entry = self._registry.get(ns, {}).get(name)
            if entry and time.time() < entry[3]:
                return None if not entry[0] else entry
            if entry:
                del self._registry[ns][name]
                if not self._registry[ns]:
                    del self._registry[ns]
                if not self.storage.save_registry(self._registry):
                    self._registry.setdefault(ns, {})[name] = entry
        return None

    def process_gossip(
        self, gossip: Dict[str, Dict[str, RegistryEntry]], owners: Dict[str, str]
    ) -> Tuple[int, int]:
        new_count = 0
        updated_count = 0
        for namespace, names in gossip.items():
            if not isinstance(names, dict):
                continue
            for name, entry in names.items():
                try:
                    rid, timestamp, signature, expiration, public_key = entry
                    identity = identity_from_public_key(public_key)
                    if not identity:
                        continue
                    expected_owner = owners.get(namespace)
                    if expected_owner is None and not self.config.get(
                        "allow_unowned_namespaces", False
                    ):
                        continue
                    if (
                        expected_owner is not None
                        and expected_owner != identity.hash.hex()
                    ):
                        continue
                    with self._lock:
                        existed = name in self._registry.get(namespace, {})
                    if self.register(
                        namespace,
                        name,
                        rid,
                        timestamp,
                        signature,
                        expiration,
                        public_key,
                    ):
                        if existed:
                            updated_count += 1
                        else:
                            new_count += 1
                except (TypeError, ValueError, OverflowError):
                    continue
        return new_count, updated_count

    def remove_unauthorized(self, namespace: str, owner_hex: str) -> int:
        removed = 0
        with self._lock:
            names = self._registry.get(namespace, {})
            removed_entries = {}
            for name in list(names):
                identity = identity_from_public_key(names[name][4])
                if not identity or identity.hash.hex() != owner_hex:
                    removed_entries[name] = names.pop(name)
                    removed += 1
            if not names and namespace in self._registry:
                del self._registry[namespace]
            if removed and not self.storage.save_registry(self._registry):
                self._registry.setdefault(namespace, {}).update(removed_entries)
                return 0
        return removed

    def reconcile_namespace_owners(
        self, owners: Dict[str, str], allow_unowned: bool
    ) -> int:
        """Remove persisted entries that are no longer authorized by namespace state."""
        removed = 0
        with self._lock:
            removed_entries: Dict[str, Dict[str, RegistryEntry]] = {}
            for namespace in list(self._registry):
                expected_owner = owners.get(namespace)
                if expected_owner is None and allow_unowned:
                    continue
                for name in list(self._registry[namespace]):
                    identity = identity_from_public_key(
                        self._registry[namespace][name][4]
                    )
                    if (
                        expected_owner is None
                        or not identity
                        or identity.hash.hex() != expected_owner
                    ):
                        removed_entries.setdefault(namespace, {})[name] = (
                            self._registry[namespace].pop(name)
                        )
                        removed += 1
                if not self._registry[namespace]:
                    del self._registry[namespace]
            if removed and not self.storage.save_registry(self._registry):
                for namespace, names in removed_entries.items():
                    self._registry.setdefault(namespace, {}).update(names)
                return 0
        return removed

    def run_ttl_check(self) -> int:
        now = time.time()
        removed = 0
        with self._lock:
            removed_entries: Dict[str, Dict[str, RegistryEntry]] = {}
            for namespace in list(self._registry):
                for name in list(self._registry[namespace]):
                    if self._registry[namespace][name][3] <= now:
                        removed_entries.setdefault(namespace, {})[name] = (
                            self._registry[namespace].pop(name)
                        )
                        removed += 1
                if not self._registry[namespace]:
                    del self._registry[namespace]
            if removed and not self.storage.save_registry(self._registry):
                for namespace, names in removed_entries.items():
                    self._registry.setdefault(namespace, {}).update(names)
                return 0
        return removed

    def get_registry_for_gossip(self) -> Dict[str, Dict[str, RegistryEntry]]:
        now = time.time()
        with self._lock:
            return {
                namespace: {
                    name: entry for name, entry in names.items() if now < entry[3]
                }
                for namespace, names in self._registry.items()
                if any(now < entry[3] for entry in names.values())
            }

    def snapshot(self) -> List[Dict[str, Any]]:
        now = time.time()
        result = []
        with self._lock:
            for namespace, names in self._registry.items():
                for name, entry in names.items():
                    if entry[0] and now < entry[3]:
                        identity = identity_from_public_key(entry[4])
                        if not identity:
                            continue
                        result.append(
                            {
                                "namespace": namespace,
                                "name": name,
                                "rid": entry[0].hex(),
                                "timestamp": entry[1],
                                "expiration": entry[3],
                                "owner": identity.hash.hex(),
                            }
                        )
        return result


class Cache:
    """A bounded process-wide LRU cache of signed registry entries."""

    def __init__(self, config: Dict[str, Any]):
        self.ttl = int(config.get("cache_ttl", 300))
        self.max_size = int(config.get("max_cache_size", 1000))
        self._cache: "OrderedDict[Tuple[str, str], CacheEntry]" = OrderedDict()
        self._lock = threading.RLock()

    def get(self, ns: str, name: str) -> Optional[RegistryEntry]:
        key = (ns, name)
        with self._lock:
            entry = self._cache.get(key)
            if not entry:
                return None
            now = time.time()
            if now - entry[1] >= self.ttl or now >= entry[0][3]:
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
            return entry[0]

    def put(self, ns: str, name: str, entry: RegistryEntry) -> None:
        key = (ns, name)
        with self._lock:
            self._cache[key] = (entry, time.time())
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_size:
                self._cache.popitem(last=False)

    def delete(self, ns: str, name: str) -> None:
        with self._lock:
            self._cache.pop((ns, name), None)

    def invalidate_namespace(self, ns: str) -> None:
        with self._lock:
            for key in [key for key in self._cache if key[0] == ns]:
                del self._cache[key]

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def run_ttl_check(self) -> int:
        now = time.time()
        with self._lock:
            expired = [
                key
                for key, entry in self._cache.items()
                if now - entry[1] >= self.ttl or now >= entry[0][3]
            ]
            for key in expired:
                del self._cache[key]
            return len(expired)
