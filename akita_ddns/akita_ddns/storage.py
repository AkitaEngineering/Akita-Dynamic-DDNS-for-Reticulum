# akita_ddns/storage.py
import time
import logging
import threading
import yaml
import os
import errno
from typing import Dict, Tuple, Optional, Any, List

from .config import get_config
from .crypto import verify_signature # Keep verify_signature for gossip processing

# Use logger specific to this module
log = logging.getLogger(__name__)

# Type Alias for Registry Entry: (rid_bytes, registration_timestamp, signature_bytes, expiration_timestamp)
RegistryEntry = Tuple[bytes, float, bytes, float]
# Type Alias for Cache Entry: (rid_bytes, cache_timestamp)
CacheEntry = Tuple[bytes, float]

class PersistentStorage:
    """Handles saving and loading state to/from YAML files atomically."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        # Use a single lock for all file operations to prevent conflicts
        self._file_lock = threading.Lock()
        log.info("PersistentStorage initialized.")
        if config.get("persist_state"):
             log.info(f"Persistence enabled. State path: {config.get('persistence_path')}")
        else:
             log.info("Persistence disabled.")


    def _save_yaml(self, data: Dict[str, Any], file_path: Optional[str]):
        """Safely saves data to a YAML file using atomic rename."""
        if not self.config.get("persist_state"):
            # Logged at init, no need to log every time
            # log.debug(f"Persistence disabled, skipping save.")
            return
        if not file_path:
             log.error("Attempted to save state but file path is None or empty.")
             return

        temp_path = file_path + ".tmp"
        log.debug(f"Attempting to save state ({len(data)} items) to {file_path} (via {temp_path})")
        with self._file_lock:
            try:
                # Ensure the directory exists right before writing
                dir_path = os.path.dirname(file_path)
                if dir_path: # Check if there's a directory part
                    os.makedirs(dir_path, exist_ok=True)

                # Write to the temporary file
                with open(temp_path, "w", encoding='utf-8') as f: # Specify encoding
                    yaml.dump(data, f, default_flow_style=False, allow_unicode=True)

                # Atomically replace the original file with the temporary file
                os.replace(temp_path, file_path)
                log.info(f"Successfully saved state to {file_path}")

            except OSError as e:
                # Handle potential errors during directory creation or file operations
                log.error(f"OS Error saving state to {file_path}: {e}", exc_info=True)
                # Clean up temp file if it exists and saving failed
                if os.path.exists(temp_path):
                    try: os.remove(temp_path)
                    except OSError: pass # Ignore cleanup error
            except Exception as e:
                log.error(f"Unexpected error saving state to {file_path}: {e}", exc_info=True)
                # Clean up temp file if it exists
                if os.path.exists(temp_path):
                    try: os.remove(temp_path)
                    except OSError: pass # Ignore cleanup error

    def _load_yaml(self, file_path: Optional[str]) -> Dict[str, Any]:
        """Safely loads data from a YAML file."""
        if not self.config.get("persist_state"):
            log.debug("Persistence disabled, skipping load.")
            return {}
        if not file_path:
             log.error("Attempted to load state but file path is None or empty.")
             return {}
        if not os.path.exists(file_path):
            log.info(f"State file {file_path} not found, starting with empty state.")
            return {}

        log.debug(f"Attempting to load state from {file_path}")
        with self._file_lock: # Lock ensures we don't read while another thread might be saving
            try:
                with open(file_path, "r", encoding='utf-8') as f: # Specify encoding
                    data = yaml.safe_load(f)
                if isinstance(data, dict):
                    log.info(f"Successfully loaded state ({len(data)} items) from {file_path}")
                    return data
                elif data is None: # Handle empty file case
                     log.info(f"State file {file_path} is empty. Returning empty state.")
                     return {}
                else:
                    log.warning(f"Invalid data format (not a dictionary) in {file_path}. Returning empty state.")
                    # Optional: Backup the corrupted file?
                    # try: os.rename(file_path, file_path + f".corrupted_{int(time.time())}") except OSError: pass
                    return {}
            except yaml.YAMLError as e:
                 log.error(f"Error parsing YAML from {file_path}: {e}. Returning empty state.", exc_info=True)
                 # Optional: Backup corrupted file
                 return {}
            except Exception as e:
                log.error(f"Unexpected error loading state from {file_path}: {e}. Returning empty state.", exc_info=True)
                # Optional: Backup corrupted file
                return {}

    def save_registry(self, registry_data: Dict[str, Dict[str, RegistryEntry]]):
        file_path = self.config.get("registry_file_path")
        serializable_registry = {}
        # No lock needed here as registry access should be locked by the caller (Registry class)
        for ns, names in registry_data.items():
            serializable_names = {}
            for name, entry_tuple in names.items():
                # Only persist entries that haven't expired
                if time.time() < entry_tuple[3]: # Index 3 is expiration time
                     try:
                          # Unpack tuple for clarity and hex conversion
                          rid, ts, sig, exp = entry_tuple
                          serializable_names[name] = (rid.hex(), ts, sig.hex(), exp)
                     except Exception as e:
                          log.warning(f"Skipping serialization of registry entry {name}@{ns} due to error: {e}")
            if serializable_names:
                serializable_registry[ns] = serializable_names
        self._save_yaml(serializable_registry, file_path)

    def load_registry(self) -> Dict[str, Dict[str, RegistryEntry]]:
        file_path = self.config.get("registry_file_path")
        serializable_registry = self._load_yaml(file_path)
        registry_data = {}
        now = time.time()
        loaded_count = 0
        expired_count = 0
        invalid_count = 0
        # Convert hex back to bytes and validate structure
        for ns, names in serializable_registry.items():
            valid_names = {}
            for name, entry in names.items():
                try:
                    # Expecting tuple: (rid_hex, ts, sig_hex, exp)
                    if not isinstance(entry, (list, tuple)) or len(entry) != 4:
                         raise TypeError("Invalid entry format - expected list/tuple of length 4")

                    rid_hex, ts_float, sig_hex, exp_float = entry

                    # Validate types before conversion
                    if not isinstance(rid_hex, str) or not isinstance(sig_hex, str) or \
                       not isinstance(ts_float, (int, float)) or not isinstance(exp_float, (int, float)):
                        raise TypeError("Invalid types within registry entry tuple")

                    # Check expiry before attempting potentially costly hex decode
                    if now >= float(exp_float):
                        expired_count +=1
                        continue

                    rid = bytes.fromhex(rid_hex)
                    sig = bytes.fromhex(sig_hex)

                    # Final structure: (rid_bytes, timestamp_float, signature_bytes, expiration_float)
                    valid_names[name] = (rid, float(ts_float), sig, float(exp_float))
                    loaded_count += 1
                except (ValueError, TypeError, IndexError) as e:
                    log.warning(f"Skipping invalid registry entry for '{name}' in '{ns}' during load: {e} - Entry data: {entry}")
                    invalid_count += 1
            if valid_names:
                registry_data[ns] = valid_names

        # Avoid logging 0 counts if file was empty/not found
        if loaded_count > 0 or expired_count > 0 or invalid_count > 0:
             log.info(f"Registry loaded: {loaded_count} valid, {expired_count} expired, {invalid_count} invalid entries skipped.")
        return registry_data

    def save_namespaces(self, namespace_owners: Dict[str, str]):
        file_path = self.config.get("namespace_owners_file_path")
        # Data is already serializable (str: str)
        self._save_yaml(namespace_owners, file_path)

    def load_namespaces(self) -> Dict[str, str]:
        file_path = self.config.get("namespace_owners_file_path")
        # Owners are stored as hex strings (RID hashes), no conversion needed
        loaded_data = self._load_yaml(file_path)
        # Basic validation: ensure keys/values are strings
        valid_data = {str(k): str(v) for k, v in loaded_data.items() if isinstance(k, str) and isinstance(v, str)}
        skipped_count = len(loaded_data) - len(valid_data)
        if skipped_count > 0:
            log.warning(f"{skipped_count} invalid entries skipped during namespace load.")
        return valid_data


    def save_reputation(self, reputation: Dict[str, int]):
        file_path = self.config.get("reputation_file_path")
        # Data is already serializable (str: int)
        self._save_yaml(reputation, file_path)

    def load_reputation(self) -> Dict[str, int]:
        file_path = self.config.get("reputation_file_path")
        # Reputation keys are hex strings (RID hashes), values are ints
        loaded_data = self._load_yaml(file_path)
        # Basic validation
        valid_data = {}
        skipped_count = 0
        for k, v in loaded_data.items():
             try:
                  # Ensure key is string-like and value is int-like
                  valid_data[str(k)] = int(v)
             except (ValueError, TypeError):
                  log.warning(f"Skipping invalid reputation entry during load: Key='{k}', Value='{v}'")
                  skipped_count += 1
        if skipped_count > 0:
            log.warning(f"{skipped_count} invalid entries skipped during reputation load.")
        return valid_data


class Registry:
    """In-memory storage for DDNS registrations with TTL management and persistence."""

    def __init__(self, storage_handler: PersistentStorage, config: Dict[str, Any]):
        self.config = config
        self.storage = storage_handler
        # {namespace: {name: (rid_bytes, reg_time_float, sig_bytes, expire_time_float)}}
        self._registry: Dict[str, Dict[str, RegistryEntry]] = {}
        self._lock = threading.RLock() # Protects access to _registry
        self._load_initial_state() # Load state during initialization

    def _load_initial_state(self):
         """Loads the registry from the persistent storage."""
         with self._lock:
              self._registry = self.storage.load_registry()
              log.info(f"Initial registry loaded with {sum(len(v) for v in self._registry.values())} entries across {len(self._registry)} namespaces.")


    def register(self, namespace: str, name: str, rid: bytes, timestamp: float, signature: bytes, expiration: float) -> bool:
        """Adds or updates a registration and persists the change."""
        with self._lock:
            new_entry = (rid, timestamp, signature, expiration)
            # Check if entry already exists and is identical (except maybe timestamp)
            # Avoid unnecessary writes if only timestamp differs slightly due to propagation
            current_entry = self._registry.get(namespace, {}).get(name)
            # Compare RID, Signature, and Expiration time. Timestamp can differ.
            if current_entry and current_entry[0] == rid and current_entry[2] == signature and current_entry[3] == expiration:
                 log.debug(f"Identical registration for {name}@{namespace} received. No update needed.")
                 return True # Treat as success, no change needed

            # Add or update the entry
            self._registry.setdefault(namespace, {})[name] = new_entry
            log.info(f"Registered/Updated '{name}' in '{namespace}' -> {rid.hex()} (Expires: {time.ctime(expiration)})")
            # Persist change immediately
            self.storage.save_registry(self._registry) # Pass the internal dict directly
        return True

    def resolve(self, namespace: str, name: str) -> Optional[RegistryEntry]:
        """
        Looks up a name in the registry, checking TTL and returning the full entry if valid.
        Removes expired entries found during lookup and persists the removal.
        """
        with self._lock:
            entry = self._registry.get(namespace, {}).get(name)
            if entry:
                # Unpack for clarity
                rid, timestamp, signature, expiration = entry
                if time.time() < expiration:
                    # Entry is valid
                    log.debug(f"Registry hit for '{name}' in '{namespace}': {rid.hex()}")
                    return entry
                else:
                    # Entry exists but is expired, remove it
                    log.info(f"Registry entry expired for '{name}' in '{namespace}'. Removing.")
                    made_change = self._remove_entry(namespace, name) # Assumes lock is held
                    if made_change:
                        # Persist removal immediately
                        self.storage.save_registry(self._registry)
                    return None # Return None as it's expired
            else:
                # Entry not found
                log.debug(f"Registry miss for '{name}' in '{namespace}'")
                return None

    def _remove_entry(self, namespace: str, name: str) -> bool:
        """Internal helper to remove an entry (assumes lock is held). Returns True if removed."""
        removed = False
        try:
            # Ensure namespace exists before trying to access name key
            if namespace in self._registry and name in self._registry[namespace]:
                del self._registry[namespace][name]
                removed = True
                # Remove the namespace key if it becomes empty
                if not self._registry[namespace]:
                    del self._registry[namespace]
                    log.debug(f"Removed empty namespace '{namespace}' from registry.")
        except KeyError:
            # This might happen in rare race conditions, but check should prevent it
            log.warning(f"KeyError during registry removal for {name}@{namespace}, likely already removed.")
            pass
        return removed

    def process_gossip(self, gossip_registry: Dict[str, Dict[str, RegistryEntry]],
                       namespace_owners: Dict[str, str], source_node_hash: bytes) -> Tuple[int, int]:
        """
        Updates the local registry based on received gossip data.
        Verifies signatures and ownership before accepting entries. Persists if changes are made.

        Args:
            gossip_registry: The received registry data (already deserialized with bytes).
            namespace_owners: Current known namespace owners for validation.
            source_node_hash: The hash of the node that sent the gossip.

        Returns:
            Tuple (new_entries_added, entries_updated)
        """
        updated_count = 0
        new_count = 0
        now = time.time()
        made_changes = False

        with self._lock:
            for namespace, names in gossip_registry.items():
                for name, gossip_entry in names.items():
                    try:
                        # Unpack gossip entry
                        rid, timestamp, signature, expiration = gossip_entry

                        # 1. Basic Validation & Expiry Check (some done in network layer, repeat robustly)
                        if not isinstance(rid, bytes) or not isinstance(signature, bytes) or \
                           not isinstance(timestamp, (int, float)) or not isinstance(expiration, (int, float)):
                            log.warning(f"Skipping invalid data type in gossip entry {name}@{namespace} from {source_node_hash.hex()}")
                            continue
                        if now >= expiration:
                            log.debug(f"Skipping expired gossip entry for {name}@{namespace}")
                            continue

                        # 2. Signature Verification
                        ttl_at_registration = int(expiration - timestamp)
                        # Ensure TTL is non-negative; could happen with clock skew or bad data
                        if ttl_at_registration < 0: ttl_at_registration = 0
                        data_to_verify = f"{namespace}:{name}:{rid.hex()}:{ttl_at_registration}".encode("utf-8")
                        if not verify_signature(data_to_verify, signature, rid):
                            log.warning(f"Gossip signature verification failed during registry processing for '{name}'@{namespace} (RID: {rid.hex()}) from {source_node_hash.hex()}.")
                            # TODO: Penalize sender reputation here
                            continue

                        # 3. Namespace Ownership Check
                        owner_rid_hex = rid.hex()
                        if namespace in namespace_owners and namespace_owners[namespace] != owner_rid_hex:
                            log.warning(f"Gossip attempt for '{name}' in owned namespace '{namespace}' by non-owner {owner_rid_hex} (Owner is {namespace_owners[namespace]}). Ignoring.")
                            continue

                        # 4. Check if newer than local entry
                        local_entry = self._registry.get(namespace, {}).get(name)
                        # Accept if no local entry OR if gossip timestamp is newer
                        # OR if gossip timestamp is same but expiration is later (handle TTL updates)
                        # OR if gossip timestamp is same, expiration same, but signature differs (rare, but possible correction)
                        should_update = False
                        if not local_entry:
                             should_update = True
                             log_reason = "new entry"
                        elif local_entry[1] < timestamp: # Compare registration timestamps (index 1)
                             should_update = True
                             log_reason = "newer timestamp"
                        elif local_entry[1] == timestamp and local_entry[3] < expiration: # Same timestamp, later expiration (index 3)
                             should_update = True
                             log_reason = "later expiration"
                        elif local_entry[1] == timestamp and local_entry[3] == expiration and local_entry[2] != signature: # Same times, different signature (index 2)
                             should_update = True
                             log_reason = "different signature"

                        if should_update:
                            self._registry.setdefault(namespace, {})[name] = gossip_entry
                            made_changes = True
                            if local_entry:
                                updated_count += 1
                                log.debug(f"Updated '{name}'@{namespace} via gossip ({log_reason}) from {source_node_hash.hex()}")
                            else:
                                new_count += 1
                                log.debug(f"Added '{name}'@{namespace} via gossip from {source_node_hash.hex()}")
                            # TODO: Reward sender reputation here

                    except Exception as e:
                         # Catch errors processing a specific entry to avoid stopping the whole gossip batch
                         log.error(f"Error processing gossip entry {name}@{namespace} from {source_node_hash.hex()}: {e}", exc_info=True)
                         continue # Skip to the next entry

        if made_changes:
            # Persist changes after processing all gossip for this batch
             self.storage.save_registry(self._registry)

        if new_count > 0 or updated_count > 0:
            log.info(f"Processed gossip from {source_node_hash.hex()}: {new_count} new, {updated_count} updated entries.")

        return new_count, updated_count

    def run_ttl_check(self):
        """Removes expired entries from the registry and persists if changes were made."""
        now = time.time()
        removed_count = 0
        made_changes = False
        log.debug("Running registry TTL check...")
        with self._lock:
            # Iterate over a copy of namespace keys and name keys to allow deletion
            for namespace in list(self._registry.keys()):
                if namespace not in self._registry: continue # Namespace might have been deleted already
                for name in list(self._registry[namespace].keys()):
                    if name not in self._registry[namespace]: continue # Name might have been deleted already
                    try:
                        # Get expiration time (index 3)
                        expiration = self._registry[namespace][name][3]
                        if now >= expiration:
                            rid_hex = self._registry[namespace][name][0].hex() # Get RID for logging before deleting
                            removed = self._remove_entry(namespace, name) # Assumes lock is held
                            if removed:
                                removed_count += 1
                                made_changes = True
                                log.info(f"Removed expired registration '{name}' in '{namespace}' (RID: {rid_hex})")
                    except (IndexError, KeyError) as e:
                         # Should not happen with checks, but log if it does
                         log.warning(f"Error accessing entry {name}@{namespace} during TTL check: {e}")
                         continue

        if removed_count > 0:
            log.info(f"Registry TTL check complete. Removed {removed_count} expired entries.")
            if made_changes:
                 # Persist removals
                 self.storage.save_registry(self._registry)
        else:
            log.debug("Registry TTL check complete. No entries expired.")

    def get_registry_for_gossip(self) -> Dict[str, Dict[str, RegistryEntry]]:
        """Returns a copy of the current valid (non-expired) registry entries."""
        valid_registry = {}
        now = time.time()
        with self._lock:
            # Create a deep copy to avoid modifying internal state accidentally
            # and filter out expired entries simultaneously
            for ns, names in self._registry.items():
                valid_names = {}
                for name, entry in names.items():
                    if now < entry[3]: # entry[3] is expiration time
                        valid_names[name] = entry # Keep the tuple directly
                if valid_names:
                    valid_registry[ns] = valid_names
        return valid_registry

    def get_local_entries(self) -> Dict[str, Dict[str, RegistryEntry]]:
         """Returns a deep copy of all local registry entries (including potentially expired)."""
         with self._lock:
              # Create a deep copy to prevent external modification
              return {ns: names.copy() for ns, names in self._registry.items()}


class Cache:
    """In-memory cache for resolved names with TTL and max size per namespace."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.cache_ttl = config.get("cache_ttl", 300)
        # Ensure max_size is at least 1 if enabled
        self.max_size_per_ns = max(1, config.get("max_cache_size", 1000))
        # {namespace: {name: (rid_bytes, cache_time_float)}}
        self._cache: Dict[str, Dict[str, CacheEntry]] = {}
        self._lock = threading.RLock() # Protects access to _cache
        log.info(f"Cache initialized: TTL={self.cache_ttl}s, MaxSizePerNS={self.max_size_per_ns}")

    def get(self, namespace: str, name: str) -> Optional[bytes]:
        """Retrieves an RID from the cache if valid (not expired)."""
        with self._lock:
            entry = self._cache.get(namespace, {}).get(name)
            if entry:
                rid, timestamp = entry
                if time.time() - timestamp < self.cache_ttl:
                    log.debug(f"Cache hit for '{name}' in '{namespace}': {rid.hex()}")
                    return rid
                else:
                    # Entry exists but is expired, remove it
                    log.debug(f"Cache expired for '{name}' in '{namespace}'. Removing.")
                    self._remove_entry(namespace, name) # Lock already held
                    return None # Return None as it's expired
            else:
                # Entry not found
                log.debug(f"Cache miss for '{name}' in '{namespace}'")
                return None

    def put(self, namespace: str, name: str, rid: bytes):
        """Adds or updates an entry in the cache."""
        if not isinstance(rid, bytes):
             log.warning(f"Attempted to cache non-bytes RID for {name}@{namespace}")
             return
        with self._lock:
            entry = (rid, time.time())
            ns_cache = self._cache.setdefault(namespace, {})
            ns_cache[name] = entry
            log.debug(f"Cached '{name}' in '{namespace}' -> {rid.hex()}")
            # Check and enforce max size for this namespace *after* adding
            if len(ns_cache) > self.max_size_per_ns:
                self._evict_oldest(namespace) # Lock already held

    def _remove_entry(self, namespace: str, name: str):
        """Internal helper to remove an entry (assumes lock is held)."""
        try:
            # Check existence before deleting to avoid KeyError if called concurrently
            if namespace in self._cache and name in self._cache[namespace]:
                del self._cache[namespace][name]
                # Remove the namespace key if it becomes empty
                if not self._cache[namespace]:
                    del self._cache[namespace]
                    log.debug(f"Removed empty namespace '{namespace}' from cache.")
        except KeyError:
             # This might happen in rare race conditions, log it
             log.warning(f"KeyError during cache removal for {name}@{namespace}, likely already removed.")
             pass # Don't raise, just log

    def _evict_oldest(self, namespace: str):
        """Removes the oldest entry from a specific namespace cache (assumes lock is held)."""
        try:
            if namespace not in self._cache: return # Namespace gone already
            ns_cache = self._cache[namespace]
            # Check if cache actually needs eviction (might have shrunk due to TTL)
            if len(ns_cache) <= self.max_size_per_ns: return

            # Find the entry with the minimum timestamp
            # Using min on dict.items() with a lambda key is efficient for moderate sizes
            oldest_name, oldest_entry = min(ns_cache.items(), key=lambda item: item[1][1]) # item[1][1] is the timestamp

            # Remove the oldest entry (use _remove_entry to handle empty namespace cleanup)
            self._remove_entry(namespace, oldest_name)
            log.debug(f"Evicted oldest cache entry '{oldest_name}' from namespace '{namespace}' due to size limit.")

        except (KeyError, ValueError):
            # Namespace might not exist or be empty if entries removed concurrently
            log.warning(f"Value or Key error during cache eviction for namespace {namespace}, possibly due to concurrent modification.")
            pass
        except Exception as e:
            log.error(f"Error evicting oldest cache entry for namespace {namespace}: {e}", exc_info=True)


    def run_ttl_check(self):
        """Removes all expired entries from the cache."""
        now = time.time()
        removed_count = 0
        log.debug("Running cache TTL check...")
        with self._lock:
            # Iterate over a copy of namespace and name keys to allow deletion
            for namespace in list(self._cache.keys()):
                 if namespace not in self._cache: continue # Namespace removed during iteration
                 for name in list(self._cache[namespace].keys()):
                      if name not in self._cache[namespace]: continue # Name removed during iteration
                      try:
                           timestamp = self._cache[namespace][name][1] # Get timestamp (index 1)
                           if now - timestamp >= self.cache_ttl:
                                self._remove_entry(namespace, name) # Lock already held
                                removed_count += 1
                      except (KeyError, IndexError):
                           # Entry might have been removed concurrently
                           log.warning(f"Error accessing entry {name}@{namespace} during cache TTL check, likely removed concurrently.")
                           continue

        if removed_count > 0:
            log.info(f"Cache TTL check complete. Removed {removed_count} expired entries.")
        else:
            log.debug("Cache TTL check complete. No entries expired.")

    def get_local_entries(self) -> Dict[str, Dict[str, CacheEntry]]:
         """Returns a deep copy of all local cache entries."""
         with self._lock:
              # Create a deep copy to prevent external modification
              return {ns: names.copy() for ns, names in self._cache.items()}

