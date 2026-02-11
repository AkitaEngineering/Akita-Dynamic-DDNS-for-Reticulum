# akita_ddns/storage.py
import time
import logging
import threading
import yaml
import os
from typing import Dict, Tuple, Optional, Any

from .config import get_config
from .crypto import verify_signature, verify_signature_with_public_key

log = logging.getLogger(__name__)

# Registry Entry: (rid_bytes, registration_timestamp, signature_bytes, expiration_timestamp, public_key_bytes)
RegistryEntry = Tuple[bytes, float, bytes, float, bytes]
# Cache Entry: (rid_bytes, cache_timestamp)
CacheEntry = Tuple[bytes, float]

class PersistentStorage:
    """Handles atomic saving and loading of state to YAML."""
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self._file_lock = threading.Lock()

    def _save_yaml(self, data: Dict, file_path: Optional[str]):
        if not self.config.get("persist_state") or not file_path: return
        
        temp_path = file_path + ".tmp"
        with self._file_lock:
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(temp_path, "w", encoding='utf-8') as f:
                    yaml.dump(data, f, default_flow_style=False)
                os.replace(temp_path, file_path)
            except Exception as e:
                log.error(f"Failed to save {file_path}: {e}")
                if os.path.exists(temp_path): os.remove(temp_path)

    def _load_yaml(self, file_path: Optional[str]) -> Dict:
        if not self.config.get("persist_state") or not file_path or not os.path.exists(file_path):
            return {}
        with self._file_lock:
            try:
                with open(file_path, "r", encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
            except Exception as e:
                log.error(f"Failed to load {file_path}: {e}")
                return {}

    def save_registry(self, registry_data: Dict[str, Dict[str, RegistryEntry]]):
        if not self.config.get("registry_file_path"): return
        serializable = {}
        for ns, names in registry_data.items():
            s_names = {}
            for name, entry in names.items():
                if time.time() < entry[3]: # Check expiry
                    s_names[name] = (entry[0].hex(), entry[1], entry[2].hex(), entry[3], entry[4].hex())
            if s_names: serializable[ns] = s_names
        self._save_yaml(serializable, self.config["registry_file_path"])

    def load_registry(self) -> Dict[str, Dict[str, RegistryEntry]]:
        raw = self._load_yaml(self.config.get("registry_file_path"))
        registry = {}
        now = time.time()
        for ns, names in raw.items():
            v_names = {}
            for name, entry in names.items():
                try:
                    if now < entry[3]: # Not expired
                        if len(entry) >= 5:
                            v_names[name] = (bytes.fromhex(entry[0]), entry[1], bytes.fromhex(entry[2]), entry[3], bytes.fromhex(entry[4]))
                except (ValueError, IndexError, TypeError): pass
            if v_names: registry[ns] = v_names
        return registry

    def save_namespaces(self, owners: Dict[str, str]):
        self._save_yaml(owners, self.config.get("namespace_owners_file_path"))

    def load_namespaces(self) -> Dict[str, str]:
        raw = self._load_yaml(self.config.get("namespace_owners_file_path"))
        return {str(k): str(v) for k, v in raw.items() if isinstance(k, str) and isinstance(v, str)}

    def save_reputation(self, rep: Dict[str, int]):
        self._save_yaml(rep, self.config.get("reputation_file_path"))

    def load_reputation(self) -> Dict[str, int]:
        raw = self._load_yaml(self.config.get("reputation_file_path"))
        return {str(k): int(v) for k, v in raw.items() if isinstance(v, int)}

class Registry:
    def __init__(self, storage: PersistentStorage, config: Dict):
        self.storage = storage
        self._lock = threading.RLock()
        self._registry = self.storage.load_registry()

    def register(self, ns: str, name: str, rid: bytes, ts: float, sig: bytes, exp: float, public_key: bytes) -> bool:
        with self._lock:
            entry = (rid, ts, sig, exp, public_key)
            curr = self._registry.get(ns, {}).get(name)
            # Optimization: don't save if identical
            if curr and curr[0] == rid and curr[2] == sig and curr[3] == exp and curr[4] == public_key: return True
            
            self._registry.setdefault(ns, {})[name] = entry
            log.info(f"Registered {name}@{ns} -> {rid.hex()}")
            self.storage.save_registry(self._registry)
        return True

    def resolve(self, ns: str, name: str) -> Optional[RegistryEntry]:
        with self._lock:
            entry = self._registry.get(ns, {}).get(name)
            if entry:
                if time.time() < entry[3]: return entry
                else:
                    del self._registry[ns][name]
                    if not self._registry[ns]: del self._registry[ns]
                    self.storage.save_registry(self._registry)
        return None

    def process_gossip(self, gossip: Dict, owners: Dict, source: bytes) -> Tuple[int, int]:
        new_c, upd_c = 0, 0
        now = time.time()
        changed = False
        with self._lock:
            for ns, names in gossip.items():
                for name, entry in names.items():
                    rid, ts, sig, exp, pubkey = entry
                    if now >= exp: continue
                    
                    # Check Ownership
                    if ns in owners and owners[ns] != rid.hex(): continue

                    # Verify Sig (Expensive, do last)
                    # Reconstruct signed payload: ns:name:rid_hex:ttl
                    ttl = int(exp - ts)
                    if ttl < 0: ttl = 0
                    payload = f"{ns}:{name}:{rid.hex()}:{ttl}".encode("utf-8")
                    if not verify_signature_with_public_key(payload, sig, pubkey): continue

                    # Update logic
                    curr = self._registry.get(ns, {}).get(name)
                    update = False
                    if not curr:
                        update = True; new_c += 1
                    elif curr[1] < ts: # Newer timestamp
                        update = True; upd_c += 1
                    elif curr[1] == ts and curr[3] < exp: # Extended TTL
                        update = True; upd_c += 1
                    
                    if update:
                        self._registry.setdefault(ns, {})[name] = entry
                        changed = True
        
        if changed: self.storage.save_registry(self._registry)
        return new_c, upd_c

    def run_ttl_check(self):
        now = time.time()
        changed = False
        with self._lock:
            for ns in list(self._registry.keys()):
                if ns not in self._registry: continue
                for name in list(self._registry[ns].keys()):
                    if self._registry[ns][name][3] <= now:
                        del self._registry[ns][name]
                        changed = True
                if not self._registry[ns]: del self._registry[ns]
        if changed: self.storage.save_registry(self._registry)

    def get_registry_for_gossip(self) -> Dict:
        # Return simple dict copy of valid entries
        res = {}
        now = time.time()
        with self._lock:
            for ns, names in self._registry.items():
                v_names = {n: e for n, e in names.items() if now < e[3]}
                if v_names: res[ns] = v_names
        return res

class Cache:
    def __init__(self, config: Dict):
        self.ttl = config.get("cache_ttl", 300)
        self.max_size = config.get("max_cache_size", 1000)
        self._cache = {}
        self._lock = threading.RLock()

    def get(self, ns: str, name: str) -> Optional[bytes]:
        with self._lock:
            entry = self._cache.get(ns, {}).get(name)
            if entry:
                if time.time() - entry[1] < self.ttl: return entry[0]
                del self._cache[ns][name]
                if not self._cache[ns]: del self._cache[ns]
        return None

    def put(self, ns: str, name: str, rid: bytes):
        with self._lock:
            ns_cache = self._cache.setdefault(ns, {})
            ns_cache[name] = (rid, time.time())
            if len(ns_cache) > self.max_size:
                # Evict oldest
                oldest = min(ns_cache.keys(), key=lambda k: ns_cache[k][1])
                del ns_cache[oldest]

    def run_ttl_check(self):
        now = time.time()
        with self._lock:
            for ns in list(self._cache.keys()):
                for name in list(self._cache[ns].keys()):
                    if now - self._cache[ns][name][1] >= self.ttl:
                        del self._cache[ns][name]
                if not self._cache[ns]: del self._cache[ns]
