import tempfile
import time

import RNS as ret

from akita_ddns.crypto import generate_signature
from akita_ddns.storage import PersistentStorage, Registry
from akita_ddns.utils import build_registration_payload


def make_storage_config(tmpdir):
    return {
        "persist_state": False,
        "registry_file_path": None,
        "namespace_owners_file_path": None,
        "reputation_file_path": None,
        "cache_ttl": 300,
        "max_cache_size": 1000,
        "storage_path": tmpdir,
    }


def test_process_gossip_accepts_namespace_owner_with_distinct_rid():
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = PersistentStorage(make_storage_config(tmpdir))
        registry = Registry(storage, {})

        owner_identity = ret.Identity()
        destination_identity = ret.Identity()
        ts = int(time.time())
        ttl = 300
        payload = build_registration_payload("secure", "node", destination_identity.hash.hex(), ttl, ts)
        signature = generate_signature(payload, owner_identity)

        gossip = {
            "secure": {
                "node": (
                    destination_identity.hash,
                    ts,
                    signature,
                    ts + ttl,
                    owner_identity.get_public_key(),
                )
            }
        }

        new_count, updated_count = registry.process_gossip(gossip, {"secure": owner_identity.hash.hex()})
        entry = registry.resolve("secure", "node")

        assert (new_count, updated_count) == (1, 0)
        assert entry is not None
        assert entry[0] == destination_identity.hash