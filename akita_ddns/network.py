"""Reticulum transport and protocol handlers."""

import asyncio
import logging
import secrets
import threading
import time
from typing import Any, Dict, Iterable, List, Tuple

import RNS as ret

from .config import get_config
from .crypto import generate_signature, identity_from_public_key
from .protocol import Command, ProtocolError, decode, encode
from .utils import (
    RateLimiter,
    build_registration_payload,
    validate_hash,
    validate_label,
    validate_public_key,
    validate_registration_times,
    validate_signature,
)

log = logging.getLogger(__name__)
APP_NAME = "akita_ddns"
_JITTER_RANDOM = secrets.SystemRandom()


class AkitaAnnounceHandler:
    def __init__(self, server: "AkitaServer"):
        self.server = server
        self.aspect_filter = f"{APP_NAME}.{server.network_id}.node"

    def received_announce(self, destination_hash, announced_identity, app_data):
        self.server.add_peer(destination_hash, announced_identity)


class AkitaServer:
    def __init__(self, r_instance, registry, cache, ns_mgr, rep_mgr, identity):
        self.r = r_instance
        self.reg = registry
        self.cache = cache
        self.ns_mgr = ns_mgr
        self.rep_mgr = rep_mgr
        self.config = get_config()
        self.network_id = self.config["akita_namespace_identity_hash"]
        if not self.network_id:
            raise ValueError(
                "Network ID must be initialized before starting the server"
            )

        self.rate_limiter = RateLimiter(self.config["rate_limit_requests_per_sec"])
        self.identity = identity
        self.known_peers: Dict[bytes, Tuple[Any, float]] = {}
        self._peer_lock = threading.Lock()
        self._gossip_cursor = 0
        self._shutdown = False

        self.listener_anycast = ret.Destination(
            None,
            ret.Destination.IN,
            ret.Destination.PLAIN,
            APP_NAME,
            self.network_id,
            "broadcast",
        )
        self.listener_anycast.set_proof_strategy(ret.Destination.PROVE_NONE)
        self.listener_anycast.set_packet_callback(self._on_packet)

        self.listener_node = ret.Destination(
            self.identity,
            ret.Destination.IN,
            ret.Destination.SINGLE,
            APP_NAME,
            self.network_id,
            "node",
        )
        self.listener_node.set_proof_strategy(ret.Destination.PROVE_NONE)
        self.listener_node.set_packet_callback(self._on_packet)
        self.listener_node.announce()

        self.announce_handler = AkitaAnnounceHandler(self)
        ret.Transport.register_announce_handler(self.announce_handler)

        self.sender = ret.Destination(
            None,
            ret.Destination.OUT,
            ret.Destination.PLAIN,
            APP_NAME,
            self.network_id,
            "broadcast",
        )

    @staticmethod
    def _send(destination, payload: bytes) -> bool:
        try:
            if len(payload) > ret.Packet.MDU:
                raise ProtocolError("Packet exceeds Reticulum MDU")
            # RNS returns None for a successful unproved packet and False on failure.
            return ret.Packet(destination, payload).send() is not False
        except Exception as exc:
            log.warning("Packet send failed: %s", exc)
            return False

    def add_peer(self, destination_hash, announced_identity) -> None:
        if not isinstance(destination_hash, bytes) or announced_identity is None:
            return
        if destination_hash == self.listener_node.hash:
            return
        with self._peer_lock:
            is_new = destination_hash not in self.known_peers
            self.known_peers[destination_hash] = (announced_identity, time.monotonic())
        if is_new:
            log.info("Discovered Akita peer: %s", destination_hash.hex())

    def _active_peers(self) -> Iterable[Any]:
        cutoff = time.monotonic() - self.config["peer_ttl"]
        with self._peer_lock:
            active = []
            for destination_hash, (identity, last_seen) in list(
                self.known_peers.items()
            ):
                if last_seen < cutoff:
                    del self.known_peers[destination_hash]
                else:
                    active.append(identity)
        yield from active

    def _broadcast_to_peers(self, payload: bytes) -> None:
        for peer_identity in self._active_peers():
            try:
                destination = ret.Destination(
                    peer_identity,
                    ret.Destination.OUT,
                    ret.Destination.SINGLE,
                    APP_NAME,
                    self.network_id,
                    "node",
                )
                self._send(destination, payload)
            except Exception as exc:
                log.warning("Could not prepare gossip destination: %s", exc)

    def _on_packet(self, data, packet) -> None:
        if self._shutdown or not packet or not self.rate_limiter.check():
            return
        try:
            message = decode(data, max_size=ret.Packet.MDU)
            command, fields = message[1], message[2:]
            handlers = {
                Command.REGISTER: self._handle_register,
                Command.GOSSIP_REGISTER: self._handle_register,
                Command.RESOLVE: self._handle_resolve,
                Command.NAMESPACE_CREATE: self._handle_ns_create,
                Command.GOSSIP_NAMESPACE_CREATE: self._handle_ns_create,
                Command.NAMESPACE_TRANSFER: self._handle_ns_transfer,
                Command.GOSSIP_NAMESPACE_TRANSFER: self._handle_ns_transfer,
            }
            handler = handlers.get(command)
            if not handler:
                raise ProtocolError("Command is not valid for a server")
            handler(fields)
        except (ProtocolError, TypeError, ValueError, OverflowError) as exc:
            log.warning("Rejected malformed packet: %s", exc)
        except Exception:
            log.exception("Unexpected packet handler error")

    def _handle_register(self, fields: List[Any]) -> bool:
        if len(fields) != 7:
            raise ProtocolError("REGISTER requires seven fields")
        namespace, name, rid, public_key, signature, ttl, timestamp = fields
        validate_label(namespace, "namespace")
        validate_label(name, "name")
        if not isinstance(rid, bytes):
            raise ValueError("RID must be bytes")
        if rid:
            validate_hash(rid, "RID")
        validate_public_key(public_key)
        validate_signature(signature)
        timestamp, ttl = validate_registration_times(
            timestamp,
            ttl,
            max_ttl=self.config["max_registration_ttl"],
            max_clock_skew=self.config["max_clock_skew"],
        )
        identity = identity_from_public_key(public_key)
        if not identity or not self.ns_mgr.is_authorized(namespace, identity.hash):
            return False
        accepted = self.reg.register(
            namespace,
            name,
            rid,
            timestamp,
            signature,
            timestamp + ttl,
            public_key,
        )
        if accepted:
            self.cache.delete(namespace, name)
            self.rep_mgr.update_reputation(identity.hash, 1)
        return accepted

    def _handle_resolve(self, fields: List[Any]) -> bool:
        if len(fields) != 4:
            raise ProtocolError("RESOLVE requires four fields")
        namespace, name, request_public_key, nonce = fields
        validate_label(namespace, "namespace")
        validate_label(name, "name")
        validate_public_key(request_public_key)
        validate_hash(nonce, "request nonce")
        request_identity = identity_from_public_key(request_public_key)
        if not request_identity:
            return False
        entry = self.cache.get(namespace, name)
        if not entry:
            entry = self.reg.resolve(namespace, name)
            if entry:
                self.cache.put(namespace, name, entry)
        if not entry:
            return False
        response = encode(
            Command.RESPONSE,
            namespace,
            name,
            entry[0],
            entry[1],
            entry[2],
            entry[3],
            entry[4],
            nonce,
            max_size=ret.Packet.MDU,
        )
        destination = ret.Destination(
            request_identity,
            ret.Destination.OUT,
            ret.Destination.SINGLE,
            APP_NAME,
            self.network_id,
            "response",
        )
        return self._send(destination, response)

    def _handle_ns_create(self, fields: List[Any]) -> bool:
        if len(fields) != 3:
            raise ProtocolError("NAMESPACE_CREATE requires three fields")
        namespace, public_key, signature = fields
        changed = self.ns_mgr.create_namespace(namespace, public_key, signature)
        if changed:
            identity = identity_from_public_key(public_key)
            if not identity:
                return False
            owner = identity.hash
            self.reg.remove_unauthorized(namespace, owner.hex())
            self.cache.invalidate_namespace(namespace)
            self.rep_mgr.update_reputation(owner, 1)
        return changed

    def _handle_ns_transfer(self, fields: List[Any]) -> bool:
        if len(fields) != 7:
            raise ProtocolError("NAMESPACE_TRANSFER requires seven fields")
        (
            namespace,
            new_owner,
            sequence,
            timestamp,
            transfer_id,
            public_key,
            signature,
        ) = fields
        changed = self.ns_mgr.transfer_namespace(
            namespace,
            public_key,
            new_owner,
            sequence,
            timestamp,
            transfer_id,
            signature,
        )
        if changed:
            self.reg.remove_unauthorized(namespace, new_owner.hex())
            self.cache.invalidate_namespace(namespace)
            self.rep_mgr.update_reputation(new_owner, 1)
        return changed

    def _gossip_messages(self) -> List[bytes]:
        messages = []
        for namespace, names in self.reg.get_registry_for_gossip().items():
            for name, entry in names.items():
                messages.append(
                    encode(
                        Command.GOSSIP_REGISTER,
                        namespace,
                        name,
                        entry[0],
                        entry[4],
                        entry[2],
                        entry[3] - entry[1],
                        entry[1],
                        max_size=ret.Packet.MDU,
                    )
                )
        for event in self.ns_mgr.get_events_for_gossip():
            if event["type"] == "create":
                messages.append(
                    encode(
                        Command.GOSSIP_NAMESPACE_CREATE,
                        event["namespace"],
                        bytes.fromhex(event["public_key"]),
                        bytes.fromhex(event["signature"]),
                        max_size=ret.Packet.MDU,
                    )
                )
            else:
                messages.append(
                    encode(
                        Command.GOSSIP_NAMESPACE_TRANSFER,
                        event["namespace"],
                        bytes.fromhex(event["new_owner"]),
                        event["sequence"],
                        event["timestamp"],
                        bytes.fromhex(event["transfer_id"]),
                        bytes.fromhex(event["public_key"]),
                        bytes.fromhex(event["signature"]),
                        max_size=ret.Packet.MDU,
                    )
                )
        return messages

    async def run_gossip_loop(self) -> None:
        while not self._shutdown:
            await asyncio.sleep(
                self.config["gossip_interval"] * _JITTER_RANDOM.uniform(0.9, 1.1)
            )
            try:
                self.listener_node.announce()
                messages = self._gossip_messages()
                if not messages:
                    continue
                limit = min(self.config["max_gossip_entries_per_cycle"], len(messages))
                selected = [
                    messages[(self._gossip_cursor + offset) % len(messages)]
                    for offset in range(limit)
                ]
                self._gossip_cursor = (self._gossip_cursor + limit) % len(messages)
                for payload in selected:
                    self._broadcast_to_peers(payload)
                    await asyncio.sleep(0)
            except Exception:
                log.exception("Error in gossip loop")

    async def run_periodic_tasks(self) -> None:
        while not self._shutdown:
            await asyncio.sleep(self.config["ttl_check_interval"])
            try:
                self.reg.run_ttl_check()
                self.cache.run_ttl_check()
            except Exception:
                log.exception("Error in maintenance loop")

    def shutdown(self) -> None:
        if self._shutdown:
            return
        self._shutdown = True
        self.listener_anycast.set_packet_callback(None)
        self.listener_node.set_packet_callback(None)
        try:
            ret.Transport.deregister_announce_handler(self.announce_handler)
        except Exception as exc:
            log.debug("Could not deregister announce handler: %s", exc)

    def send_register(self, name, namespace, rid, identity, ttl) -> bool:
        validate_label(namespace, "namespace")
        validate_label(name, "name")
        validate_hash(rid, "RID")
        timestamp = int(time.time())
        validate_registration_times(
            timestamp,
            ttl,
            max_ttl=self.config["max_registration_ttl"],
            max_clock_skew=self.config["max_clock_skew"],
        )
        data = build_registration_payload(namespace, name, rid.hex(), ttl, timestamp)
        signature = generate_signature(data, identity)
        if not signature:
            return False
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
        return self._send(self.sender, message)

    def register_local(self, name: str, namespace: str, rid: bytes, ttl: int) -> bool:
        timestamp = int(time.time())
        payload = build_registration_payload(namespace, name, rid.hex(), ttl, timestamp)
        signature = generate_signature(payload, self.identity)
        if not signature:
            return False
        return self._handle_register(
            [
                namespace,
                name,
                rid,
                self.identity.get_public_key(),
                signature,
                ttl,
                timestamp,
            ]
        )
