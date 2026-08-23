"""Command-line client for Akita DDNS."""

import argparse
import math
import os
import secrets
import sys
import threading
import time
from typing import Any, Dict, Optional

import RNS as ret
import yaml

from .crypto import (
    generate_signature,
    identity_from_public_key,
    verify_signature_with_public_key,
)
from .namespace import NamespaceManager
from .network import APP_NAME
from .protocol import Command, ProtocolError, decode, encode
from .storage import PersistentStorage, Registry
from .utils import (
    HASH_BYTES,
    build_namespace_create_payload,
    build_namespace_transfer_payload,
    build_registration_payload,
    load_or_create_identity,
    parse_name,
    validate_hash,
    validate_label,
    validate_public_key,
    validate_registration_times,
    validate_signature,
)


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def _send(destination, payload: bytes) -> bool:
    try:
        return ret.Packet(destination, payload).send() is not False
    except Exception:
        return False


class ResolutionReceiver:
    def __init__(self, config: Dict[str, Any], namespace_manager: NamespaceManager):
        self.config = config
        self.namespace_manager = namespace_manager
        self.event = threading.Event()
        self.value: Optional[str] = None
        self.namespace = ""
        self.name = ""
        self.nonce = b""

    def begin(self, namespace: str, name: str) -> bytes:
        self.namespace = namespace
        self.name = name
        self.nonce = secrets.token_bytes(HASH_BYTES)
        self.value = None
        self.event.clear()
        return self.nonce

    def on_response(self, data, packet) -> None:
        try:
            message = decode(data, max_size=ret.Packet.MDU)
            if message[1] is not Command.RESPONSE or len(message[2:]) != 8:
                return
            (
                namespace,
                name,
                rid,
                timestamp,
                signature,
                expiration,
                public_key,
                nonce,
            ) = message[2:]
            if (
                namespace != self.namespace
                or name != self.name
                or nonce != self.nonce
                or not packet
            ):
                return
            validate_label(namespace, "namespace")
            validate_label(name, "name")
            validate_hash(rid, "RID")
            validate_public_key(public_key)
            validate_signature(signature)
            ttl = expiration - timestamp
            validate_registration_times(
                timestamp,
                ttl,
                max_ttl=self.config["max_registration_ttl"],
                max_clock_skew=self.config["max_clock_skew"],
            )
            payload = build_registration_payload(
                namespace, name, rid.hex(), ttl, timestamp
            )
            if not verify_signature_with_public_key(payload, signature, public_key):
                return
            signer = identity_from_public_key(public_key)
            if not signer:
                return
            owners = self.namespace_manager.get_owners()
            expected_owner = owners.get(namespace)
            if expected_owner is None and not self.config["allow_unowned_namespaces"]:
                return
            if expected_owner is not None and expected_owner != signer.hash.hex():
                return
            self.value = rid.hex()
            self.event.set()
        except (ProtocolError, TypeError, ValueError, OverflowError):
            return


def _load_identity(args, config: Dict[str, Any]):
    requested_path = getattr(args, "identity", None) or getattr(
        args, "owner_identity", None
    )
    if requested_path:
        identity = ret.Identity.from_file(
            os.path.abspath(os.path.expanduser(requested_path))
        )
        if not identity:
            raise ValueError("Could not load the requested identity file")
        return identity
    return load_or_create_identity(
        os.path.join(config["storage_path"], "akita_identity")
    )


def _sender(config: Dict[str, Any]):
    return ret.Destination(
        None,
        ret.Destination.OUT,
        ret.Destination.PLAIN,
        APP_NAME,
        config["akita_namespace_identity_hash"],
        "broadcast",
    )


def _print_state(args, config: Dict[str, Any]) -> int:
    storage = PersistentStorage(config)
    printed = False
    if args.registry:
        registry = Registry(storage, config)
        print(
            yaml.safe_dump({"registry": registry.snapshot()}, sort_keys=True).rstrip()
        )
        printed = True
    if args.namespaces:
        manager = NamespaceManager(storage, config)
        print(
            yaml.safe_dump(
                {"namespaces": manager.get_owners()}, sort_keys=True
            ).rstrip()
        )
        printed = True
    if args.reputation:
        print(
            yaml.safe_dump(
                {"reputation": storage.load_reputation()}, sort_keys=True
            ).rstrip()
        )
        printed = True
    if not printed:
        print(
            "Select at least one of --registry, --namespaces, or --reputation.",
            file=sys.stderr,
        )
        return 2
    return 0


def run_cli(args, config: Dict[str, Any], r_instance=None) -> int:
    """Execute one CLI command and return a process exit status."""
    if args.command == "list":
        return _print_state(args, config)

    try:
        identity = _load_identity(args, config)
        sender = _sender(config)
        storage = PersistentStorage(config)
        namespace_manager = NamespaceManager(storage, config)

        if args.command in {"register", "revoke"}:
            name, namespace = parse_name(
                args.name, config["akita_namespace_identity_hash"]
            )
            if not namespace_manager.is_authorized(namespace, identity.hash):
                raise ValueError(
                    "The selected identity is not authorized for this namespace"
                )
            if args.command == "revoke":
                rid = b""
                ttl = config["max_registration_ttl"]
            else:
                rid = bytes.fromhex(args.rid) if args.rid else identity.hash
                validate_hash(rid, "RID")
                ttl = args.ttl if args.ttl is not None else config["default_ttl"]
            timestamp = int(time.time())
            validate_registration_times(
                timestamp,
                ttl,
                max_ttl=config["max_registration_ttl"],
                max_clock_skew=config["max_clock_skew"],
            )
            payload = build_registration_payload(
                namespace, name, rid.hex(), ttl, timestamp
            )
            signature = generate_signature(payload, identity)
            if not signature:
                raise RuntimeError("Failed to sign request")
            message = encode(
                Command.REGISTER,
                namespace,
                name,
                rid,
                identity.get_public_key(),
                signature,
                ttl,
                timestamp,
                max_size=ret.Packet.MDU,
            )
            if not _send(sender, message):
                print("Failed to send request.", file=sys.stderr)
                return 1
            action = "Revocation" if args.command == "revoke" else "Registration"
            print(f"{action} sent for {name}@{namespace}")
            return 0

        if args.command in {"resolve", "watch"}:
            name, namespace = parse_name(
                args.name, config["akita_namespace_identity_hash"]
            )
            receiver = ResolutionReceiver(config, namespace_manager)
            listener = ret.Destination(
                identity,
                ret.Destination.IN,
                ret.Destination.SINGLE,
                APP_NAME,
                config["akita_namespace_identity_hash"],
                "response",
            )
            listener.set_proof_strategy(ret.Destination.PROVE_NONE)
            listener.set_packet_callback(receiver.on_response)
            listener.announce()

            def resolve_once(timeout: float) -> Optional[str]:
                nonce = receiver.begin(namespace, name)
                message = encode(
                    Command.RESOLVE,
                    namespace,
                    name,
                    identity.get_public_key(),
                    nonce,
                    max_size=ret.Packet.MDU,
                )
                if not _send(sender, message):
                    raise RuntimeError("Failed to send resolve request")
                return receiver.value if receiver.event.wait(timeout) else None

            if args.command == "resolve":
                print(f"Resolving {name}@{namespace}...")
                value = resolve_once(args.timeout)
                if value is None:
                    print("Resolution timed out.", file=sys.stderr)
                    return 1
                print(f"Resolved: {value}")
                return 0

            print(
                f"Watching {name}@{namespace} every {args.interval}s (Ctrl+C to stop)..."
            )
            last_value = object()
            try:
                while True:
                    cycle_started = time.monotonic()
                    value = resolve_once(min(5.0, float(args.interval)))
                    if value != last_value:
                        status = value if value is not None else "unresolved"
                        print(
                            f"[{time.strftime('%H:%M:%S')}] {name}@{namespace}: {status}"
                        )
                        last_value = value
                    time.sleep(
                        max(0.0, args.interval - (time.monotonic() - cycle_started))
                    )
            except KeyboardInterrupt:
                print("\nWatch stopped.")
                return 0

        if args.command == "create_namespace":
            namespace = validate_label(args.namespace, "namespace")
            if identity.hash.hex() != config["akita_namespace_identity_hash"]:
                raise ValueError(
                    "Namespace creation requires the configured network-authority identity"
                )
            payload = build_namespace_create_payload(namespace, identity.hash)
            signature = generate_signature(payload, identity)
            if not signature:
                raise RuntimeError("Failed to sign namespace request")
            message = encode(
                Command.NAMESPACE_CREATE,
                namespace,
                identity.get_public_key(),
                signature,
                max_size=ret.Packet.MDU,
            )
            if not _send(sender, message):
                print("Failed to send namespace creation.", file=sys.stderr)
                return 1
            print(f"Namespace creation sent for {namespace}")
            return 0

        if args.command == "transfer_namespace":
            namespace = validate_label(args.namespace, "namespace")
            new_owner = bytes.fromhex(args.new_owner)
            validate_hash(new_owner, "new owner")
            sequence = namespace_manager.get_sequence(namespace)
            if sequence is None:
                print(
                    "Namespace ownership is not present in local state; synchronize this node before transferring.",
                    file=sys.stderr,
                )
                return 1
            if namespace_manager.get_owners().get(namespace) != identity.hash.hex():
                raise ValueError("The selected identity does not own this namespace")
            timestamp = int(time.time())
            transfer_id = secrets.token_bytes(HASH_BYTES)
            payload = build_namespace_transfer_payload(
                namespace, new_owner, sequence, timestamp, transfer_id
            )
            signature = generate_signature(payload, identity)
            if not signature:
                raise RuntimeError("Failed to sign namespace transfer")
            message = encode(
                Command.NAMESPACE_TRANSFER,
                namespace,
                new_owner,
                sequence,
                timestamp,
                transfer_id,
                identity.get_public_key(),
                signature,
                max_size=ret.Packet.MDU,
            )
            if not _send(sender, message):
                print("Failed to send namespace transfer.", file=sys.stderr)
                return 1
            print(f"Namespace transfer sent for {namespace} to {new_owner.hex()}")
            return 0

        raise ValueError(f"Unsupported command: {args.command}")
    except (OSError, RuntimeError, TypeError, ValueError, ProtocolError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def setup_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Akita DDNS client")
    subparsers = parser.add_subparsers(dest="command", required=True)

    register = subparsers.add_parser("register", help="publish or update a name")
    register.add_argument("--name", required=True)
    register.add_argument("--rid")
    register.add_argument("--ttl", type=_positive_int)
    register.add_argument("--identity")

    resolve = subparsers.add_parser("resolve", help="resolve one name")
    resolve.add_argument("--name", required=True)
    resolve.add_argument("--timeout", type=_positive_float, default=5.0)
    resolve.add_argument("--identity")

    create = subparsers.add_parser("create_namespace", help="claim a namespace")
    create.add_argument("--namespace", required=True)
    create.add_argument("--owner_identity")

    revoke = subparsers.add_parser("revoke", help="publish a signed tombstone")
    revoke.add_argument("--name", required=True)
    revoke.add_argument("--identity")

    transfer = subparsers.add_parser(
        "transfer_namespace", help="transfer an owned namespace"
    )
    transfer.add_argument("--namespace", required=True)
    transfer.add_argument("--new_owner", required=True)
    transfer.add_argument("--identity")

    watch = subparsers.add_parser("watch", help="watch a name for changes")
    watch.add_argument("--name", required=True)
    watch.add_argument("--interval", type=_positive_int, default=10)
    watch.add_argument("--identity")

    listing = subparsers.add_parser("list", help="inspect persisted local state")
    listing.add_argument("--registry", action="store_true")
    listing.add_argument("--namespaces", action="store_true")
    listing.add_argument("--reputation", action="store_true")
    return parser
