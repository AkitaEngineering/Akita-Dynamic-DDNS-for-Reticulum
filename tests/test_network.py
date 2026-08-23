import time
import types

import pytest
import RNS as ret

import akita_ddns.network as network_module
from akita_ddns.crypto import generate_signature
from akita_ddns.namespace import NamespaceManager
from akita_ddns.network import AkitaServer
from akita_ddns.protocol import Command, decode, encode
from akita_ddns.reputation import ReputationManager
from akita_ddns.storage import Cache, PersistentStorage, Registry
from akita_ddns.utils import build_namespace_create_payload, build_registration_payload


class AllowAllRateLimiter:
    def check(self):
        return True


def bare_server():
    server = AkitaServer.__new__(AkitaServer)
    server._shutdown = False
    server.rate_limiter = AllowAllRateLimiter()
    return server


def test_on_packet_dispatches_versioned_message_without_source_hash():
    server = bare_server()
    seen = []
    server._handle_register = lambda fields: seen.append(("REGISTER", fields))
    server._handle_resolve = lambda fields: seen.append(("RESOLVE", fields))
    server._handle_ns_create = lambda fields: seen.append(("NAMESPACE_CREATE", fields))
    server._handle_ns_transfer = lambda fields: seen.append(
        ("NAMESPACE_TRANSFER", fields)
    )
    packet = encode(Command.REGISTER, "testns", "testname", max_size=ret.Packet.MDU)

    server._on_packet(packet, types.SimpleNamespace())

    assert seen == [("REGISTER", ["testns", "testname"])]


def test_on_packet_rejects_legacy_text_protocol():
    server = bare_server()
    seen = []
    server._handle_register = lambda fields: seen.append(fields)
    server._handle_resolve = lambda fields: seen.append(fields)
    server._handle_ns_create = lambda fields: seen.append(fields)
    server._handle_ns_transfer = lambda fields: seen.append(fields)

    server._on_packet(b"REGISTER:unsigned:legacy", types.SimpleNamespace())

    assert seen == []


def test_send_treats_none_as_reticulum_success(monkeypatch):
    class Packet:
        MDU = 464

        def __init__(self, destination, payload):
            pass

        def send(self):
            return None

    monkeypatch.setattr(ret, "Packet", Packet)

    assert AkitaServer._send(object(), b"valid") is True


def test_server_only_announces_single_destination(monkeypatch):
    announcements = []

    class Destination:
        IN = ret.Destination.IN
        OUT = ret.Destination.OUT
        PLAIN = ret.Destination.PLAIN
        SINGLE = ret.Destination.SINGLE
        PROVE_NONE = ret.Destination.PROVE_NONE

        def __init__(self, identity, direction, destination_type, *aspects):
            self.type = destination_type
            self.hash = b"self" if destination_type == self.SINGLE else b"plain"

        def set_proof_strategy(self, strategy):
            pass

        def set_packet_callback(self, callback):
            pass

        def announce(self):
            if self.type == self.PLAIN:
                raise TypeError("PLAIN destinations cannot be announced")
            announcements.append(self.type)

    class Transport:
        @staticmethod
        def register_announce_handler(handler):
            pass

    class Component:
        pass

    config = {
        "akita_namespace_identity_hash": "0" * 32,
        "rate_limit_requests_per_sec": 10,
        "peer_ttl": 900,
    }
    identity = ret.Identity()
    monkeypatch.setattr(network_module.ret, "Destination", Destination)
    monkeypatch.setattr(network_module.ret, "Transport", Transport)
    monkeypatch.setattr(network_module, "get_config", lambda: config)

    AkitaServer(None, Component(), Component(), Component(), Component(), identity)

    assert announcements == [Destination.SINGLE]


def integrated_server(tmp_path, owner):
    config = {
        "persist_state": False,
        "registry_file_path": None,
        "namespace_owners_file_path": None,
        "reputation_file_path": None,
        "max_state_file_bytes": 1024 * 1024,
        "max_registration_ttl": 604800,
        "max_clock_skew": 300,
        "max_registry_size": 100,
        "cache_ttl": 300,
        "max_cache_size": 100,
        "max_namespaces": 100,
        "allow_unowned_namespaces": False,
        "akita_namespace_identity_hash": owner.hash.hex(),
    }
    storage = PersistentStorage(config)
    server = AkitaServer.__new__(AkitaServer)
    server.config = config
    server.reg = Registry(storage, config)
    server.cache = Cache(config)
    server.ns_mgr = NamespaceManager(storage, config)
    server.rep_mgr = ReputationManager(storage, config)
    server.identity = owner
    return server


def claim_namespace(server, owner, namespace="secure"):
    payload = build_namespace_create_payload(namespace, owner.hash)
    signature = generate_signature(payload, owner)
    assert server._handle_ns_create([namespace, owner.get_public_key(), signature])


def test_register_handler_verifies_owner_and_updates_registry(tmp_path):
    owner = ret.Identity()
    server = integrated_server(tmp_path, owner)
    claim_namespace(server, owner)
    rid = ret.Identity().hash
    timestamp = int(time.time())
    payload = build_registration_payload("secure", "router", rid.hex(), 300, timestamp)
    signature = generate_signature(payload, owner)

    accepted = server._handle_register(
        ["secure", "router", rid, owner.get_public_key(), signature, 300, timestamp]
    )

    assert accepted
    assert server.reg.resolve("secure", "router")[0] == rid
    assert (
        server.rep_mgr.get_reputation(owner.hash) == 2
    )  # namespace claim + registration


def test_register_handler_rejects_non_owner(tmp_path):
    owner = ret.Identity()
    attacker = ret.Identity()
    server = integrated_server(tmp_path, owner)
    claim_namespace(server, owner)
    rid = ret.Identity().hash
    timestamp = int(time.time())
    payload = build_registration_payload("secure", "router", rid.hex(), 300, timestamp)

    accepted = server._handle_register(
        [
            "secure",
            "router",
            rid,
            attacker.get_public_key(),
            generate_signature(payload, attacker),
            300,
            timestamp,
        ]
    )

    assert not accepted
    assert server.reg.resolve("secure", "router") is None


def test_register_handler_rejects_non_bytes_rid_as_malformed(tmp_path):
    owner = ret.Identity()
    server = integrated_server(tmp_path, owner)
    claim_namespace(server, owner)

    with pytest.raises(ValueError, match="RID must be bytes"):
        server._handle_register(
            ["secure", "router", "", owner.get_public_key(), b"x" * 64, 300, 1]
        )


def test_gossip_uses_one_bounded_message_per_record(tmp_path):
    owner = ret.Identity()
    server = integrated_server(tmp_path, owner)
    claim_namespace(server, owner)
    rid = ret.Identity().hash
    timestamp = int(time.time())
    payload = build_registration_payload("secure", "router", rid.hex(), 300, timestamp)
    signature = generate_signature(payload, owner)
    assert server._handle_register(
        ["secure", "router", rid, owner.get_public_key(), signature, 300, timestamp]
    )

    messages = server._gossip_messages()
    commands = [decode(message)[1] for message in messages]

    assert commands == [Command.GOSSIP_REGISTER, Command.GOSSIP_NAMESPACE_CREATE]
    assert all(len(message) <= ret.Packet.MDU for message in messages)


def test_resolution_uses_read_through_cache(tmp_path, monkeypatch):
    owner = ret.Identity()
    requester = ret.Identity()
    server = integrated_server(tmp_path, owner)
    server.network_id = owner.hash.hex()
    claim_namespace(server, owner)
    rid = ret.Identity().hash
    timestamp = int(time.time())
    ttl = 300
    payload = build_registration_payload("secure", "router", rid.hex(), ttl, timestamp)
    complete_entry = (
        rid,
        timestamp,
        generate_signature(payload, owner),
        timestamp + ttl,
        owner.get_public_key(),
    )
    assert server.reg.register("secure", "router", *complete_entry)
    sent = []
    monkeypatch.setattr(
        server, "_send", lambda destination, payload: sent.append(payload) or True
    )

    assert server._handle_resolve(
        ["secure", "router", requester.get_public_key(), b"a" * 16]
    )
    monkeypatch.setattr(
        server.reg,
        "resolve",
        lambda namespace, name: (_ for _ in ()).throw(
            AssertionError("registry should not be consulted on a cache hit")
        ),
    )
    assert server._handle_resolve(
        ["secure", "router", requester.get_public_key(), b"b" * 16]
    )
    assert len(sent) == 2
