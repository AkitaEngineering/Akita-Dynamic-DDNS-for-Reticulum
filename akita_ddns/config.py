# akita_ddns/config.py
import yaml
import os
import logging
import reticulum as ret
import threading
from typing import Dict, Any

# --- Default Configuration Values ---
DEFAULT_CONFIG = {
    "storage_path": os.path.expanduser("~/.config/reticulum"),
    "akita_namespace_identity_hash": None,
    "akita_port": 48000,
    "update_interval": 3600,
    "cache_ttl": 300,
    "log_level": "INFO",
    "max_cache_size": 1000,
    "gossip_interval": 120,
    "ttl_check_interval": 600,
    "default_ttl": 86400,
    "rate_limit_requests_per_sec": 10.0,
    "persist_state": True,
    "persistence_path": "./akita_state",
    "namespace_owners_file": "namespaces.yaml",
    "registry_file": "registry.yaml",
    "reputation_file": "reputation.yaml",
}

_config: Dict[str, Any] = {}
_config_loaded = False
_load_lock = threading.Lock()

# Initial basic logging
logging.basicConfig(level="INFO", format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
log = logging.getLogger(__name__)

def load_config(config_path: str = "akita_config.yaml") -> Dict[str, Any]:
    """Loads, validates, and returns the configuration."""
    global _config, _config_loaded
    with _load_lock:
        if _config_loaded:
            return _config

        loaded_config = {}
        effective_config = DEFAULT_CONFIG.copy()

        log.info(f"Loading configuration from: {config_path}")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    loaded_config = yaml.safe_load(f)
                    if isinstance(loaded_config, dict):
                        effective_config.update(loaded_config)
                    else:
                        log.warning(f"Config file '{config_path}' invalid. Using defaults.")
            except Exception as e:
                log.error(f"Error loading config file: {e}. Using defaults.")
        else:
            log.info(f"Config file '{config_path}' not found. Using defaults.")

        # --- Validation & Setup ---
        try:
            # Storage Path
            storage_path = effective_config.get("storage_path", DEFAULT_CONFIG["storage_path"])
            effective_config["storage_path"] = os.path.expanduser(str(storage_path))
            if not os.path.isdir(effective_config["storage_path"]):
                try:
                    os.makedirs(effective_config["storage_path"], exist_ok=True)
                    log.info(f"Created Reticulum storage: {effective_config['storage_path']}")
                except Exception as e:
                    log.error(f"Failed to create storage dir: {e}")

            # Namespace Identity Hash
            ns_hash_str = effective_config.get("akita_namespace_identity_hash")
            if ns_hash_str:
                try:
                    ns_hash_bytes = bytes.fromhex(str(ns_hash_str))
                    if len(ns_hash_bytes) != ret.Identity.HASHLENGTH // 8:
                        raise ValueError("Invalid hash length")
                    effective_config["akita_namespace_identity_hash"] = str(ns_hash_str)
                    log.info(f"Network Hash: {ns_hash_str}")
                except (ValueError, TypeError) as e:
                    log.error(f"Invalid network hash in config: {e}. Generating ephemeral.")
                    effective_config["akita_namespace_identity_hash"] = ret.Identity().hash.hex()
            else:
                effective_config["akita_namespace_identity_hash"] = ret.Identity().hash.hex()
                log.warning(f"No network hash configured. Generated ephemeral: {effective_config['akita_namespace_identity_hash']}")

            # Numeric Types
            for key in ["akita_port", "update_interval", "cache_ttl", "max_cache_size",
                        "gossip_interval", "ttl_check_interval", "default_ttl"]:
                try:
                    effective_config[key] = int(effective_config.get(key, DEFAULT_CONFIG[key]))
                except (ValueError, TypeError):
                    effective_config[key] = DEFAULT_CONFIG[key]
            
            try:
                 effective_config["rate_limit_requests_per_sec"] = float(effective_config.get("rate_limit_requests_per_sec", 10.0))
            except (ValueError, TypeError):
                 effective_config["rate_limit_requests_per_sec"] = 10.0

            # Persistence Paths
            effective_config["persist_state"] = bool(effective_config.get("persist_state", True))
            if effective_config["persist_state"]:
                p_path = os.path.expanduser(str(effective_config.get("persistence_path", "./akita_state")))
                effective_config["persistence_path"] = p_path
                if not os.path.isdir(p_path):
                    try:
                        os.makedirs(p_path, exist_ok=True)
                    except Exception as e:
                        log.error(f"Failed to create persistence dir: {e}. Disabling persistence.")
                        effective_config["persist_state"] = False
                
                if effective_config["persist_state"]:
                    effective_config["namespace_owners_file_path"] = os.path.join(p_path, effective_config.get("namespace_owners_file", "namespaces.yaml"))
                    effective_config["registry_file_path"] = os.path.join(p_path, effective_config.get("registry_file", "registry.yaml"))
                    effective_config["reputation_file_path"] = os.path.join(p_path, effective_config.get("reputation_file", "reputation.yaml"))
                else:
                    effective_config["namespace_owners_file_path"] = None
                    effective_config["registry_file_path"] = None
                    effective_config["reputation_file_path"] = None
            else:
                effective_config["namespace_owners_file_path"] = None
                effective_config["registry_file_path"] = None
                effective_config["reputation_file_path"] = None

            # Logging Level
            log_level_str = str(effective_config.get("log_level", "INFO")).upper()
            log_level_int = getattr(logging, log_level_str, logging.INFO)
            logging.getLogger().setLevel(log_level_int)
            for handler in logging.getLogger().handlers:
                handler.setLevel(log_level_int)
            
        except Exception as e:
             log.critical(f"Config validation failed: {e}", exc_info=True)
             raise

        _config = effective_config
        _config_loaded = True
        return _config

def get_config() -> Dict[str, Any]:
    if not _config_loaded:
        load_config()
    return _config
