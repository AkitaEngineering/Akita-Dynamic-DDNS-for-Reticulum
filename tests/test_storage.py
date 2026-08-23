import os
import time

import pytest
import RNS as ret

from akita_ddns.crypto import generate_signature
from akita_ddns.storage import Cache, PersistentStorage, Registry, StorageError
from akita_ddns.utils import build_registration_payload


def make_storage_config(tmp_path, persist=False):
    return {
        "persist_state": persist,
        "registry_file_path": str(tmp_path / "registry.yaml") if persist else None,
        "namespace_owners_file_path": str(tmp_path / "namespaces.yaml")
        if persist
        else None,
        "reputation_file_path": str(tmp_path / "reputation.yaml") if persist else None,
        "max_state_file_bytes": 1024 * 1024,
        "max_registration_ttl": 604800,
        "max_clock_skew": 300,
        "max_registry_size": 10,
        "cache_ttl": 300,
        "max_cache_size": 2,
    }


def signed_entry(
    identity, namespace="secure", name="node", rid=None, timestamp=None, ttl=300
):
    rid = rid if rid is not None else ret.Identity().hash
    timestamp = timestamp if timestamp is not None else int(time.time())
    payload = build_registration_payload(namespace, name, rid.hex(), ttl, timestamp)
    return (
        rid,
        timestamp,
        generate_signature(payload, identity),
        timestamp + ttl,
        identity.get_public_key(),
    )


def test_process_gossip_accepts_namespace_owner_with_distinct_rid(tmp_path):
    storage = PersistentStorage(make_storage_config(tmp_path))
    registry = Registry(storage, storage.config)
    owner = ret.Identity()
    entry = signed_entry(owner)

    counts = registry.process_gossip(
        {"secure": {"node": entry}}, {"secure": owner.hash.hex()}
    )

    assert counts == (1, 0)
    assert registry.resolve("secure", "node")[0] == entry[0]


def test_registry_rejects_invalid_signature(tmp_path):
    storage = PersistentStorage(make_storage_config(tmp_path))
    registry = Registry(storage, storage.config)
    owner = ret.Identity()
    entry = list(signed_entry(owner))
    entry[2] = b"x" * 64

    assert registry.register("secure", "node", *entry) is False


def test_signed_tombstone_blocks_older_record(tmp_path):
    storage = PersistentStorage(make_storage_config(tmp_path))
    registry = Registry(storage, storage.config)
    owner = ret.Identity()
    now = int(time.time())
    live = signed_entry(owner, timestamp=now - 1, ttl=300)
    assert registry.register("secure", "node", *live)

    tombstone = signed_entry(owner, rid=b"", timestamp=now, ttl=604800)
    assert registry.register("secure", "node", *tombstone)
    assert registry.resolve("secure", "node") is None
    assert registry.register("secure", "node", *live) is False


def test_cache_limit_is_global_lru(tmp_path):
    cache = Cache(make_storage_config(tmp_path))
    owner = ret.Identity()
    one = signed_entry(owner, namespace="one", name="a")
    two = signed_entry(owner, namespace="two", name="b")
    three = signed_entry(owner, namespace="three", name="c")
    cache.put("one", "a", one)
    cache.put("two", "b", two)
    assert cache.get("one", "a") == one  # make this most recently used
    cache.put("three", "c", three)

    assert cache.get("two", "b") is None
    assert cache.get("one", "a") == one
    assert cache.get("three", "c") == three


def test_reconcile_removes_entries_from_unowned_namespaces(tmp_path):
    storage = PersistentStorage(make_storage_config(tmp_path))
    registry = Registry(storage, storage.config)
    owner = ret.Identity()
    entry = signed_entry(owner, namespace="open")
    assert registry.register("open", "node", *entry)

    assert registry.reconcile_namespace_owners({}, allow_unowned=False) == 1
    assert registry.resolve("open", "node") is None


def test_persisted_registry_is_private_and_signature_checked(tmp_path):
    config = make_storage_config(tmp_path, persist=True)
    storage = PersistentStorage(config)
    registry = Registry(storage, config)
    owner = ret.Identity()
    entry = signed_entry(owner)
    assert registry.register("secure", "node", *entry)
    assert os.stat(config["registry_file_path"]).st_mode & 0o777 == 0o600

    loaded = Registry(PersistentStorage(config), config)
    assert loaded.resolve("secure", "node")[0] == entry[0]

    text = (tmp_path / "registry.yaml").read_text(encoding="utf-8")
    (tmp_path / "registry.yaml").write_text(
        text.replace(entry[2].hex(), "00" * 64), encoding="utf-8"
    )
    corrupted = Registry(PersistentStorage(config), config)
    assert corrupted.resolve("secure", "node") is None


def test_registry_rolls_back_when_persistence_fails(tmp_path, monkeypatch):
    storage = PersistentStorage(make_storage_config(tmp_path, persist=True))
    registry = Registry(storage, storage.config)
    owner = ret.Identity()
    entry = signed_entry(owner)
    monkeypatch.setattr(storage, "save_registry", lambda data: False)

    assert registry.register("secure", "node", *entry) is False
    assert registry.resolve("secure", "node") is None


def test_malformed_state_file_fails_closed(tmp_path):
    config = make_storage_config(tmp_path, persist=True)
    (tmp_path / "registry.yaml").write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(StorageError, match="state root"):
        Registry(PersistentStorage(config), config)


def test_oversized_state_write_is_rejected_before_replace(tmp_path):
    config = make_storage_config(tmp_path, persist=True)
    config["max_state_file_bytes"] = 1024
    storage = PersistentStorage(config)

    assert not storage._save_yaml({"value": "x" * 2048}, config["registry_file_path"])
    assert not (tmp_path / "registry.yaml").exists()


def test_state_loader_rejects_symlinks(tmp_path):
    config = make_storage_config(tmp_path, persist=True)
    target = tmp_path / "target.yaml"
    target.write_text("{}\n", encoding="utf-8")
    (tmp_path / "registry.yaml").symlink_to(target)

    with pytest.raises(StorageError, match="regular file"):
        Registry(PersistentStorage(config), config)
