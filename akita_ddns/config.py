"""Configuration loading and validation."""

import logging
import math
import os
import threading
from typing import Any, Dict, Optional

import RNS as ret
import yaml

_UNSET = None
MAX_CONFIG_FILE_BYTES = 1024 * 1024
DEFAULT_CONFIG: Dict[str, Any] = {
    "storage_path": "~/.config/reticulum",
    "akita_namespace_identity_hash": None,
    "cache_ttl": 300,
    "log_level": "INFO",
    "max_cache_size": 1000,
    "max_registry_size": 10000,
    "max_namespaces": 1000,
    "allow_unowned_namespaces": False,
    "max_registration_ttl": 604800,
    "max_clock_skew": 300,
    "max_gossip_entries_per_cycle": 100,
    "gossip_interval": 120,
    "peer_ttl": 900,
    "ttl_check_interval": 60,
    "default_ttl": 86400,
    "rate_limit_requests_per_sec": 10.0,
    "persist_state": True,
    "persistence_path": "./akita_state",
    "max_state_file_bytes": 16 * 1024 * 1024,
    "namespace_owners_file": "namespaces.yaml",
    "registry_file": "registry.yaml",
    "reputation_file": "reputation.yaml",
    "web_ui_enabled": True,
    "web_ui_host": "127.0.0.1",
    "web_ui_port": 48080,
    "web_ui_allow_mutations": False,
    "web_ui_api_token": _UNSET,
    "web_ui_max_request_bytes": 16384,
}

_config: Dict[str, Any] = {}
_config_loaded = False
_loaded_config_path: Optional[str] = None
_load_lock = threading.Lock()

logging.basicConfig(
    level="INFO", format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
log = logging.getLogger(__name__)


class ConfigurationError(ValueError):
    """Raised when configuration is unsafe or invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConfigurationError("Configuration keys must be scalar") from exc
        if duplicate:
            raise ConfigurationError(f"Duplicate configuration key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _as_bool(value: Any, key: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "on"}:
            return True
        if normalized in {"false", "no", "0", "off"}:
            return False
    raise ConfigurationError(f"{key} must be a boolean")


def _as_int(value: Any, key: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise ConfigurationError(f"{key} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError as exc:
            raise ConfigurationError(f"{key} must be an integer") from exc
    else:
        raise ConfigurationError(f"{key} must be an integer")
    if not minimum <= parsed <= maximum:
        raise ConfigurationError(f"{key} must be between {minimum} and {maximum}")
    return parsed


def _as_float(value: Any, key: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ConfigurationError(f"{key} must be a number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(f"{key} must be a number") from exc
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ConfigurationError(f"{key} must be between {minimum} and {maximum}")
    return parsed


def _resolve_path(value: Any, config_dir: str, key: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{key} must be a non-empty path")
    path = os.path.expanduser(value.strip())
    if not os.path.isabs(path):
        path = os.path.join(config_dir, path)
    return os.path.abspath(path)


def _validate_filename(value: Any, key: str) -> str:
    try:
        encoded_length = len(value.encode("utf-8")) if isinstance(value, str) else 0
    except UnicodeEncodeError:
        encoded_length = 256
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or encoded_length > 255
        or any(ord(character) < 32 for character in value)
        or value != os.path.basename(value)
    ):
        raise ConfigurationError(
            f"{key} must be a safe filename without directory components"
        )
    return value


def load_config(config_path: str = "akita_config.yaml") -> Dict[str, Any]:
    """Load one YAML configuration file and fail fast on unsafe values."""
    global _config, _config_loaded, _loaded_config_path
    normalized_path = os.path.abspath(os.path.expanduser(config_path))

    with _load_lock:
        if _config_loaded and _loaded_config_path == normalized_path:
            return _config

        loaded: Dict[str, Any] = {}
        if os.path.exists(normalized_path):
            try:
                if os.path.getsize(normalized_path) > MAX_CONFIG_FILE_BYTES:
                    raise ConfigurationError(
                        f"Configuration file exceeds {MAX_CONFIG_FILE_BYTES} bytes"
                    )
                with open(normalized_path, "r", encoding="utf-8") as handle:
                    loader = _UniqueKeyLoader(handle)
                    try:
                        raw = loader.get_single_data()
                    finally:
                        loader.dispose()
            except ConfigurationError:
                raise
            except (OSError, yaml.YAMLError) as exc:
                raise ConfigurationError(
                    f"Could not load {normalized_path}: {exc}"
                ) from exc
            if raw is not None and not isinstance(raw, dict):
                raise ConfigurationError("Configuration root must be a mapping")
            loaded = raw or {}
        else:
            log.warning(
                "Configuration file %s was not found; using safe defaults",
                normalized_path,
            )

        if any(not isinstance(key, str) for key in loaded):
            raise ConfigurationError("Configuration option names must be strings")
        unknown = sorted(set(loaded) - set(DEFAULT_CONFIG))
        if unknown:
            raise ConfigurationError(
                f"Unknown configuration option(s): {', '.join(unknown)}"
            )

        cfg = {**DEFAULT_CONFIG, **loaded}
        config_dir = os.path.dirname(normalized_path)
        cfg["storage_path"] = _resolve_path(
            cfg["storage_path"], config_dir, "storage_path"
        )
        cfg["persistence_path"] = _resolve_path(
            cfg["persistence_path"], config_dir, "persistence_path"
        )

        integer_limits = {
            "cache_ttl": (1, 86400),
            "max_cache_size": (1, 1_000_000),
            "max_registry_size": (1, 1_000_000),
            "max_namespaces": (1, 100_000),
            "max_registration_ttl": (1, 31_536_000),
            "max_clock_skew": (0, 86400),
            "max_gossip_entries_per_cycle": (1, 10000),
            "gossip_interval": (1, 86400),
            "peer_ttl": (2, 604800),
            "ttl_check_interval": (1, 86400),
            "default_ttl": (1, 31_536_000),
            "max_state_file_bytes": (1024, 1024 * 1024 * 1024),
            "web_ui_port": (1, 65535),
            "web_ui_max_request_bytes": (1024, 1024 * 1024),
        }
        for key, (minimum, maximum) in integer_limits.items():
            cfg[key] = _as_int(cfg[key], key, minimum, maximum)

        if cfg["default_ttl"] > cfg["max_registration_ttl"]:
            raise ConfigurationError("default_ttl cannot exceed max_registration_ttl")
        if cfg["peer_ttl"] <= cfg["gossip_interval"]:
            raise ConfigurationError("peer_ttl must be greater than gossip_interval")

        cfg["rate_limit_requests_per_sec"] = _as_float(
            cfg["rate_limit_requests_per_sec"],
            "rate_limit_requests_per_sec",
            0.01,
            100000.0,
        )
        for key in (
            "persist_state",
            "allow_unowned_namespaces",
            "web_ui_enabled",
            "web_ui_allow_mutations",
        ):
            cfg[key] = _as_bool(cfg[key], key)

        network_hash = cfg["akita_namespace_identity_hash"]
        if network_hash is not None:
            if not isinstance(network_hash, str):
                raise ConfigurationError(
                    "akita_namespace_identity_hash must be hexadecimal"
                )
            try:
                decoded_hash = bytes.fromhex(network_hash)
            except ValueError as exc:
                raise ConfigurationError(
                    "akita_namespace_identity_hash must be hexadecimal"
                ) from exc
            hash_length = int(getattr(ret.Identity, "TRUNCATED_HASHLENGTH", 128)) // 8
            if len(decoded_hash) != hash_length:
                raise ConfigurationError(
                    f"akita_namespace_identity_hash must contain {hash_length * 2} hex characters"
                )
            cfg["akita_namespace_identity_hash"] = decoded_hash.hex()

        log_level = str(cfg["log_level"]).upper()
        if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ConfigurationError(
                "log_level must be DEBUG, INFO, WARNING, ERROR, or CRITICAL"
            )
        cfg["log_level"] = log_level

        host = cfg["web_ui_host"]
        if (
            not isinstance(host, str)
            or not host.strip()
            or any(ord(character) < 32 for character in host)
        ):
            raise ConfigurationError("web_ui_host must be a non-empty string")
        cfg["web_ui_host"] = host.strip()
        environment_token = os.environ.get("AKITA_WEB_UI_API_TOKEN")
        if environment_token:
            cfg["web_ui_api_token"] = environment_token
        token = cfg["web_ui_api_token"]
        if token is not None and (not isinstance(token, str) or len(token) < 32):
            raise ConfigurationError(
                "web_ui_api_token must contain at least 32 characters"
            )
        if cfg["web_ui_allow_mutations"] and not token:
            raise ConfigurationError(
                "web_ui_api_token is required when web_ui_allow_mutations is enabled"
            )

        for key in ("namespace_owners_file", "registry_file", "reputation_file"):
            cfg[key] = _validate_filename(cfg[key], key)
        state_filenames = [
            cfg["namespace_owners_file"],
            cfg["registry_file"],
            cfg["reputation_file"],
        ]
        if len(set(state_filenames)) != len(state_filenames):
            raise ConfigurationError("Persistence filenames must be distinct")

        try:
            os.makedirs(cfg["storage_path"], mode=0o700, exist_ok=True)
            if cfg["persist_state"]:
                os.makedirs(cfg["persistence_path"], mode=0o700, exist_ok=True)
        except OSError as exc:
            raise ConfigurationError(
                f"Could not create configured storage directory: {exc}"
            ) from exc

        if cfg["persist_state"]:
            cfg["namespace_owners_file_path"] = os.path.join(
                cfg["persistence_path"], cfg["namespace_owners_file"]
            )
            cfg["registry_file_path"] = os.path.join(
                cfg["persistence_path"], cfg["registry_file"]
            )
            cfg["reputation_file_path"] = os.path.join(
                cfg["persistence_path"], cfg["reputation_file"]
            )
        else:
            cfg["namespace_owners_file_path"] = None
            cfg["registry_file_path"] = None
            cfg["reputation_file_path"] = None

        level = getattr(logging, log_level)
        logging.getLogger().setLevel(level)
        for handler in logging.getLogger().handlers:
            handler.setLevel(level)

        _config = cfg
        _config_loaded = True
        _loaded_config_path = normalized_path
        return _config


def ensure_network_id(config: Dict[str, Any], identity: ret.Identity) -> str:
    """Use the persisted node identity as a stable single-node network ID if omitted."""
    configured = config.get("akita_namespace_identity_hash")
    if configured:
        return str(configured)
    configured = identity.hash.hex()
    config["akita_namespace_identity_hash"] = configured
    log.warning(
        "No shared network ID was configured; using this node's stable identity hash %s",
        configured,
    )
    return configured


def get_config() -> Dict[str, Any]:
    if not _config_loaded:
        load_config()
    return _config
