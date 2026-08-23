import time
import types

import RNS as ret

import akita_ddns.cli as cli_module
from akita_ddns.cli import ResolutionReceiver, run_cli, setup_cli_parser
from akita_ddns.crypto import generate_signature
from akita_ddns.namespace import NamespaceManager
from akita_ddns.protocol import Command, decode, encode
from akita_ddns.storage import PersistentStorage
from akita_ddns.utils import build_registration_payload


def cli_config(tmp_path, authority, allow_unowned=True):
    return {
        "storage_path": str(tmp_path),
        "persist_state": False,
        "namespace_owners_file_path": None,
        "registry_file_path": None,
        "reputation_file_path": None,
        "max_namespaces": 100,
        "max_clock_skew": 300,
        "max_registration_ttl": 604800,
        "default_ttl": 300,
        "allow_unowned_namespaces": allow_unowned,
        "akita_namespace_identity_hash": authority.hash.hex(),
    }


def test_run_cli_register_emits_signed_binary_packet(tmp_path, monkeypatch, capsys):
    identity = ret.Identity()
    config = cli_config(tmp_path, identity)
    sent = []
    monkeypatch.setattr(cli_module, "_load_identity", lambda args, cfg: identity)
    monkeypatch.setattr(cli_module, "_sender", lambda cfg: object())
    monkeypatch.setattr(
        cli_module, "_send", lambda destination, payload: sent.append(payload) or True
    )
    args = setup_cli_parser().parse_args(
        ["register", "--name", "router.open", "--ttl", "60"]
    )

    status = run_cli(args, config)

    message = decode(sent[0], max_size=ret.Packet.MDU)
    assert status == 0
    assert message[1] is Command.REGISTER
    assert message[2:4] == ["open", "router"]
    assert "Registration sent" in capsys.readouterr().out


def test_run_cli_rejects_unauthorized_namespace_locally(tmp_path, monkeypatch, capsys):
    authority = ret.Identity()
    identity = ret.Identity()
    config = cli_config(tmp_path, authority, allow_unowned=False)
    monkeypatch.setattr(cli_module, "_load_identity", lambda args, cfg: identity)
    monkeypatch.setattr(cli_module, "_sender", lambda cfg: object())
    args = setup_cli_parser().parse_args(["register", "--name", "router.closed"])

    status = run_cli(args, config)

    assert status == 2
    assert "not authorized" in capsys.readouterr().err


def test_resolution_receiver_verifies_signed_entry(tmp_path):
    owner = ret.Identity()
    config = cli_config(tmp_path, owner, allow_unowned=True)
    manager = NamespaceManager(PersistentStorage(config), config)
    receiver = ResolutionReceiver(config, manager)
    nonce = receiver.begin("open", "router")
    rid = ret.Identity().hash
    timestamp = int(time.time())
    ttl = 300
    payload = build_registration_payload("open", "router", rid.hex(), ttl, timestamp)
    signature = generate_signature(payload, owner)
    response = encode(
        Command.RESPONSE,
        "open",
        "router",
        rid,
        timestamp,
        signature,
        timestamp + ttl,
        owner.get_public_key(),
        nonce,
        max_size=ret.Packet.MDU,
    )

    receiver.on_response(response, types.SimpleNamespace())

    assert receiver.event.is_set()
    assert receiver.value == rid.hex()


def test_resolution_receiver_rejects_wrong_nonce(tmp_path):
    owner = ret.Identity()
    config = cli_config(tmp_path, owner, allow_unowned=True)
    manager = NamespaceManager(PersistentStorage(config), config)
    receiver = ResolutionReceiver(config, manager)
    receiver.begin("open", "router")
    rid = ret.Identity().hash
    timestamp = int(time.time())
    ttl = 300
    payload = build_registration_payload("open", "router", rid.hex(), ttl, timestamp)
    response = encode(
        Command.RESPONSE,
        "open",
        "router",
        rid,
        timestamp,
        generate_signature(payload, owner),
        timestamp + ttl,
        owner.get_public_key(),
        b"x" * 16,
    )

    receiver.on_response(response, types.SimpleNamespace())

    assert not receiver.event.is_set()
