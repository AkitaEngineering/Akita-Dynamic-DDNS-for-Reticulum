import secrets
import time

import RNS as ret

from akita_ddns.crypto import generate_signature
from akita_ddns.namespace import NamespaceManager
from akita_ddns.storage import PersistentStorage
from akita_ddns.utils import (
    build_namespace_create_payload,
    build_namespace_transfer_payload,
)


def config(tmp_path, authority):
    return {
        "persist_state": False,
        "namespace_owners_file_path": None,
        "max_namespaces": 10,
        "max_clock_skew": 300,
        "allow_unowned_namespaces": False,
        "akita_namespace_identity_hash": authority.hash.hex(),
    }


def create(manager, namespace, identity):
    payload = build_namespace_create_payload(namespace, identity.hash)
    signature = generate_signature(payload, identity)
    return manager.create_namespace(namespace, identity.get_public_key(), signature)


def transfer(manager, namespace, old_owner, new_owner, sequence=1, transfer_id=None):
    timestamp = int(time.time())
    transfer_id = transfer_id or secrets.token_bytes(16)
    payload = build_namespace_transfer_payload(
        namespace, new_owner.hash, sequence, timestamp, transfer_id
    )
    signature = generate_signature(payload, old_owner)
    return manager.transfer_namespace(
        namespace,
        old_owner.get_public_key(),
        new_owner.hash,
        sequence,
        timestamp,
        transfer_id,
        signature,
    )


def test_namespace_create_and_transfer_chain(tmp_path):
    first = ret.Identity()
    second = ret.Identity()
    settings = config(tmp_path, first)
    manager = NamespaceManager(PersistentStorage(settings), settings)

    assert create(manager, "secure", first)
    assert transfer(manager, "secure", first, second)

    assert manager.get_owners() == {"secure": second.hash.hex()}
    assert manager.get_sequence("secure") == 2


def test_transfer_replay_is_rejected(tmp_path):
    first = ret.Identity()
    second = ret.Identity()
    settings = config(tmp_path, first)
    manager = NamespaceManager(PersistentStorage(settings), settings)
    assert create(manager, "secure", first)
    transfer_id = secrets.token_bytes(16)

    assert transfer(manager, "secure", first, second, transfer_id=transfer_id)
    assert not transfer(manager, "secure", first, second, transfer_id=transfer_id)


def test_only_network_authority_can_create_namespace(tmp_path):
    authority = ret.Identity()
    attacker = ret.Identity()
    settings = config(tmp_path, authority)
    manager = NamespaceManager(PersistentStorage(settings), settings)

    assert not create(manager, "secure", attacker)
    assert create(manager, "secure", authority)
    assert manager.get_owners()["secure"] == authority.hash.hex()


def test_unowned_namespaces_are_closed_by_default(tmp_path):
    authority = ret.Identity()
    settings = config(tmp_path, authority)
    manager = NamespaceManager(PersistentStorage(settings), settings)

    assert not manager.is_authorized("unclaimed", authority.hash)
