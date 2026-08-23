"""Signed, persistent namespace ownership chains."""

import copy
import logging
import threading
import time
from typing import Any, Dict, List, Optional

from .crypto import identity_from_public_key, verify_signature_with_public_key
from .storage import PersistentStorage
from .utils import (
    build_namespace_create_payload,
    build_namespace_transfer_payload,
    validate_hash,
    validate_label,
    validate_public_key,
    validate_signature,
)

log = logging.getLogger(__name__)


class NamespaceManager:
    """Track namespace chains rooted in the configured network authority."""

    def __init__(self, storage: PersistentStorage, config: Dict[str, Any]):
        self.storage = storage
        self.max_namespaces = int(config.get("max_namespaces", 1000))
        self.max_clock_skew = int(config.get("max_clock_skew", 300))
        self.allow_unowned = bool(config.get("allow_unowned_namespaces", False))
        self.authority = config.get("akita_namespace_identity_hash")
        if not isinstance(self.authority, str):
            raise ValueError("Namespace authority/network ID is not initialized")
        self._lock = threading.RLock()
        self._records: Dict[str, Dict[str, Any]] = {}
        self._load(storage.load_namespaces())

    def _load(self, raw: Dict[str, Any]) -> None:
        for namespace, record in raw.items():
            if not isinstance(record, dict) or not isinstance(
                record.get("events"), list
            ):
                log.warning(
                    "Ignoring unverifiable legacy namespace record %r", namespace
                )
                continue
            events = record["events"]
            if not events:
                continue
            try:
                create = events[0]
                self.create_namespace(
                    namespace,
                    bytes.fromhex(create["public_key"]),
                    bytes.fromhex(create["signature"]),
                    persist=False,
                )
                for event in events[1:]:
                    if event.get("type") != "transfer":
                        raise ValueError("unknown namespace event")
                    if not self.transfer_namespace(
                        namespace,
                        bytes.fromhex(event["public_key"]),
                        bytes.fromhex(event["new_owner"]),
                        int(event["sequence"]),
                        int(event["timestamp"]),
                        bytes.fromhex(event["transfer_id"]),
                        bytes.fromhex(event["signature"]),
                        persist=False,
                        allow_historical=True,
                    ):
                        raise ValueError("invalid ownership chain")
            except (KeyError, TypeError, ValueError):
                log.warning("Ignoring invalid namespace ownership chain %r", namespace)
                self._records.pop(namespace, None)

    def _save(self) -> None:
        self.storage.save_namespaces(self._records)

    def create_namespace(
        self,
        ns: str,
        owner_pubkey: bytes,
        sig: bytes,
        *,
        persist: bool = True,
    ) -> bool:
        validate_label(ns, "namespace")
        validate_public_key(owner_pubkey)
        validate_signature(sig)
        identity = identity_from_public_key(owner_pubkey)
        if not identity:
            return False
        owner = identity.hash
        payload = build_namespace_create_payload(ns, owner)
        if not verify_signature_with_public_key(payload, sig, owner_pubkey):
            log.warning("Invalid signature for namespace %s", ns)
            return False

        owner_hex = owner.hex()
        if owner_hex != self.authority:
            log.warning(
                "Rejected namespace %s: signer is not the network authority", ns
            )
            return False
        event = {
            "type": "create",
            "public_key": owner_pubkey.hex(),
            "signature": sig.hex(),
        }
        with self._lock:
            current = self._records.get(ns)
            if current:
                return False
            if len(self._records) >= self.max_namespaces:
                log.warning("Namespace capacity reached; refusing %s", ns)
                return False
            self._records[ns] = {
                "root": owner_hex,
                "owner": owner_hex,
                "events": [event],
            }
            if persist:
                self._save()
        log.info("Created namespace %s owner %s", ns, owner_hex)
        return True

    def transfer_namespace(
        self,
        ns: str,
        old_owner_pubkey: bytes,
        new_owner: bytes,
        sequence: int,
        timestamp: int,
        transfer_id: bytes,
        sig: bytes,
        *,
        persist: bool = True,
        allow_historical: bool = False,
    ) -> bool:
        validate_label(ns, "namespace")
        validate_public_key(old_owner_pubkey)
        validate_hash(new_owner, "new owner")
        validate_signature(sig)
        validate_hash(transfer_id, "transfer ID")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ValueError("sequence must be a positive integer")
        if (
            isinstance(timestamp, bool)
            or not isinstance(timestamp, int)
            or timestamp <= 0
        ):
            raise ValueError("timestamp must be a positive integer")
        if timestamp > int(time.time()) + self.max_clock_skew:
            raise ValueError("transfer timestamp is too far in the future")

        identity = identity_from_public_key(old_owner_pubkey)
        if not identity:
            return False
        payload = build_namespace_transfer_payload(
            ns, new_owner, sequence, timestamp, transfer_id
        )
        if not verify_signature_with_public_key(payload, sig, old_owner_pubkey):
            log.warning("Invalid signature for namespace transfer %s", ns)
            return False

        event = {
            "type": "transfer",
            "new_owner": new_owner.hex(),
            "sequence": sequence,
            "timestamp": timestamp,
            "transfer_id": transfer_id.hex(),
            "public_key": old_owner_pubkey.hex(),
            "signature": sig.hex(),
        }
        with self._lock:
            record = self._records.get(ns)
            if not record:
                return False
            events: List[Dict[str, Any]] = record["events"]
            if sequence > len(events):
                return False

            if sequence < len(events):
                existing = events[sequence]
                if existing == event:
                    return False
                if existing.get("transfer_id", "") <= transfer_id.hex():
                    return False
                prior_owner = self._owner_before_event(record, sequence)
                if prior_owner != identity.hash.hex():
                    return False
                events = events[:sequence]
                record["events"] = events
                record["owner"] = prior_owner

            if record["owner"] != identity.hash.hex():
                return False
            if any(item.get("transfer_id") == transfer_id.hex() for item in events):
                return False
            if len(events) >= 10000:
                log.warning("Transfer history limit reached for namespace %s", ns)
                return False

            events.append(event)
            record["owner"] = new_owner.hex()
            if persist:
                self._save()
        log.info(
            "Transferred namespace %s to %s at sequence %s",
            ns,
            new_owner.hex(),
            sequence,
        )
        return True

    @staticmethod
    def _owner_before_event(record: Dict[str, Any], sequence: int) -> str:
        owner = record["root"]
        for event in record["events"][1:sequence]:
            owner = event["new_owner"]
        return owner

    def is_authorized(self, ns: str, potential_owner: bytes) -> bool:
        validate_label(ns, "namespace")
        validate_hash(potential_owner, "owner")
        with self._lock:
            record = self._records.get(ns)
            return (record is None and self.allow_unowned) or (
                record is not None and record["owner"] == potential_owner.hex()
            )

    def get_owners(self) -> Dict[str, str]:
        with self._lock:
            return {
                namespace: record["owner"]
                for namespace, record in self._records.items()
            }

    def get_sequence(self, ns: str) -> Optional[int]:
        with self._lock:
            record = self._records.get(ns)
            return len(record["events"]) if record else None

    def get_events_for_gossip(self) -> List[Dict[str, Any]]:
        with self._lock:
            result = []
            for namespace, record in self._records.items():
                for event in record["events"]:
                    result.append({"namespace": namespace, **copy.deepcopy(event)})
            return result
