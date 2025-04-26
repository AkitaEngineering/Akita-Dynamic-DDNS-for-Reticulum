# akita_ddns/config.py
import yaml
import os
import logging
import reticulum as ret
import threading
from typing import Dict, Any, Optional

# --- Default Configuration Values ---
DEFAULT_CONFIG = {
    "storage_path": os.path.expanduser("~/.config/reticulum"),
    "akita_namespace_identity_hash": None, # Must be set for a real network
    "akita_port": 48000,
    "update_interval": 3600,      # 1 hour
    "cache_ttl": 300,           # 5 minutes
    "log_level": "INFO",
    "max_cache_size": 1000,
    "gossip_interval": 120,     # 2 minutes
    "ttl_check_interval": 600,  # 10 minutes
    "default_ttl": 86400,       # 1 day
    "rate_limit_requests_per_sec": 10.0, # Use float for rate limiter
    "persist_state": True,
    "persistence_path": "./akita_state",
    "namespace_owners_file": "namespaces.yaml",
    "registry_file": "registry.yaml",
    "reputation_file": "reputation.yaml",
}

# Global config dictionary and loading state management
_config: Dict[str, Any] = {}
_config_loaded = False
_load_lock = threading.Lock()

# Configure root logger initially - will be updated by load_config
logging.basicConfig(level="INFO", format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
log = logging.getLogger(__name__) # Logger for this module


def load_config(config_path: str = "akita_config.yaml") -> Dict[str, Any]:
    """
    Loads configuration from a YAML file, merges with defaults, and validates.
    This function is thread-safe and ensures config is loaded only once.

    Args:
        config_path: Path to the YAML configuration file.

    Returns:
        The loaded and validated configuration dictionary.

    Raises:
        ValueError: If configuration validation fails critically.
    """
    global _config, _config_loaded
    with _load_lock:
        if _config_loaded:
            return _config

        loaded_config = {}
        effective_config = DEFAULT_CONFIG.copy() # Start with defaults

        log.info(f"Attempting to load configuration from: {config_path}")
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    loaded_config = yaml.safe_load(f)
                    if not isinstance(loaded_config, dict):
                        log.warning(f"Config file '{config_path}' is not a valid dictionary. Using defaults.")
                        loaded_config = {}
            except Exception as e:
                log.error(f"Error loading config file '{config_path}': {e}. Using defaults.")
                loaded_config = {}
        else:
            log.info(f"Config file '{config_path}' not found. Using default configuration.")
            # Consider creating a default config file here if desired for first run
            # try:
            #     with open(config_path, "w") as f:
            #         yaml.dump(DEFAULT_CONFIG, f, default_flow_style=False)
            #     log.info(f"Created default config file at '{config_path}'")
            # except Exception as e:
            #     log.error(f"Could not write default config file '{config_path}': {e}")

        # Merge loaded config over defaults
        effective_config.update(loaded_config)

        # --- Validation and Type Conversion ---
        try:
            # Ensure storage path exists
            storage_path = effective_config.get("storage_path", DEFAULT_CONFIG["storage_path"])
            effective_config["storage_path"] = os.path.expanduser(str(storage_path))
            if not os.path.isdir(effective_config["storage_path"]):
                try:
                    os.makedirs(effective_config["storage_path"], exist_ok=True)
                    log.info(f"Created Reticulum storage directory: {effective_config['storage_path']}")
                except Exception as e:
                    # Log error but allow proceeding, Reticulum might handle it or fail later
                    log.error(f"Failed to create Reticulum storage directory {effective_config['storage_path']}: {e}. This might cause issues.")

            # Validate/Generate Akita Namespace Identity Hash
            ns_hash_str = effective_config.get("akita_namespace_identity_hash")
            if ns_hash_str:
                try:
                    ns_hash_bytes = bytes.fromhex(str(ns_hash_str)) # Ensure it's treated as string first
                    if len(ns_hash_bytes) != ret.Identity.HASHLENGTH // 8:
                        raise ValueError(f"Invalid hash length ({len(ns_hash_bytes)} bytes), expected {ret.Identity.HASHLENGTH // 8}")
                    effective_config["akita_namespace_identity_hash"] = str(ns_hash_str) # Store as string
                    log.info(f"Using configured Akita Namespace Identity Hash: {ns_hash_str}")
                except (ValueError, TypeError) as e:
                    log.error(f"Invalid 'akita_namespace_identity_hash' in config: {e}. Generating ephemeral hash.")
                    effective_config["akita_namespace_identity_hash"] = ret.Identity().hash.hex()
                    log.warning(f"Generated ephemeral Akita Namespace Identity Hash: {effective_config['akita_namespace_identity_hash']}. Nodes will not interconnect unless this hash matches.")
            else:
                effective_config["akita_namespace_identity_hash"] = ret.Identity().hash.hex()
                log.warning(f"No 'akita_namespace_identity_hash' configured. Generated ephemeral hash: {effective_config['akita_namespace_identity_hash']}. Nodes will not interconnect unless this hash matches.")

            # Ensure numeric types are correct
            for key in ["akita_port", "update_interval", "cache_ttl", "max_cache_size",
                        "gossip_interval", "ttl_check_interval", "default_ttl"]:
                try:
                    effective_config[key] = int(effective_config.get(key, DEFAULT_CONFIG[key]))
                except (ValueError, TypeError):
                    log.warning(f"Invalid integer value for '{key}' in config. Using default: {DEFAULT_CONFIG[key]}")
                    effective_config[key] = DEFAULT_CONFIG[key]

            # Ensure rate limit is float
            try:
                 effective_config["rate_limit_requests_per_sec"] = float(effective_config.get("rate_limit_requests_per_sec", DEFAULT_CONFIG["rate_limit_requests_per_sec"]))
            except (ValueError, TypeError):
                 log.warning(f"Invalid float value for 'rate_limit_requests_per_sec'. Using default: {DEFAULT_CONFIG['rate_limit_requests_per_sec']}")
                 effective_config["rate_limit_requests_per_sec"] = DEFAULT_CONFIG["rate_limit_requests_per_sec"]


            # Validate log level
            log_level_str = str(effective_config.get("log_level", DEFAULT_CONFIG["log_level"])).upper()
            if hasattr(logging, log_level_str):
                 effective_config["log_level"] = log_level_str
            else:
                 log.warning(f"Invalid log level '{log_level_str}'. Using default: {DEFAULT_CONFIG['log_level']}")
                 effective_config["log_level"] = DEFAULT_CONFIG["log_level"]


            # Ensure persistence path exists if persistence is enabled
            effective_config["persist_state"] = bool(effective_config.get("persist_state", DEFAULT_CONFIG["persist_state"]))
            if effective_config["persist_state"]:
                persist_path = effective_config.get("persistence_path", DEFAULT_CONFIG["persistence_path"])
                effective_config["persistence_path"] = os.path.expanduser(str(persist_path))
                if not os.path.isdir(effective_config["persistence_path"]):
                    try:
                        os.makedirs(effective_config["persistence_path"], exist_ok=True)
                        log.info(f"Created persistence directory: {effective_config['persistence_path']}")
                    except Exception as e:
                        log.error(f"Failed to create persistence directory {effective_config['persistence_path']}: {e}. Persistence disabled.")
                        effective_config["persist_state"] = False
                # Construct full paths for state files only if persist_state is still true
                if effective_config["persist_state"]:
                    effective_config["namespace_owners_file_path"] = os.path.join(effective_config["persistence_path"], effective_config.get("namespace_owners_file", DEFAULT_CONFIG["namespace_owners_file"]))
                    effective_config["registry_file_path"] = os.path.join(effective_config["persistence_path"], effective_config.get("registry_file", DEFAULT_CONFIG["registry_file"]))
                    effective_config["reputation_file_path"] = os.path.join(effective_config["persistence_path"], effective_config.get("reputation_file", DEFAULT_CONFIG["reputation_file"]))
                else: # Ensure paths are None if persistence disabled after trying to create dir
                     effective_config["namespace_owners_file_path"] = None
                     effective_config["registry_file_path"] = None
                     effective_config["reputation_file_path"] = None

            else: # Ensure paths are None if persistence disabled from the start
                effective_config["namespace_owners_file_path"] = None
                effective_config["registry_file_path"] = None
                effective_config["reputation_file_path"] = None


        except Exception as e:
             log.critical(f"Failed during configuration validation: {e}", exc_info=True)
             raise ValueError("Configuration validation failed.") from e


        # --- Apply Logging Level ---
        # Get the root logger and set its level. Also configure the handler.
        log_level_int = getattr(logging, effective_config["log_level"])
        root_logger = logging.getLogger() # Get root logger
        root_logger.setLevel(log_level_int)

        # Update level on existing handlers (created by basicConfig)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
        for handler in root_logger.handlers:
            handler.setLevel(log_level_int)
            handler.setFormatter(formatter) # Apply consistent formatter

        log.info(f"Logging level set to {effective_config['log_level']}")

        # Store the final config and mark as loaded
        _config = effective_config
        _config_loaded = True
        log.info("Configuration loaded and validated successfully.")
        log.debug(f"Effective configuration: {_config}")

        return _config

def get_config() -> Dict[str, Any]:
    """
    Returns the globally loaded configuration dictionary.
    Loads it using the default path if it hasn't been loaded yet.
    """
    if not _config_loaded:
        # This might be called before main() explicitly loads config,
        # e.g., if a module is imported and uses get_config() at the top level.
        # It assumes the default config file path ("akita_config.yaml") is okay.
        log.debug("Config accessed before explicit load, loading with default path.")
        load_config() # Load using default path "akita_config.yaml"
    return _config

