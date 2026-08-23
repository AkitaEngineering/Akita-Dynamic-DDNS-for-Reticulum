# Testing and release verification

## Automated suite

Install development dependencies and run all checks from the repository root:

```bash
python -m pip install -r requirements-dev.txt
pytest -q
python -m compileall -q akita_ddns tests
mypy akita_ddns
ruff check akita_ddns tests
ruff format --check akita_ddns tests
python -m build
python -m pip check
```

The suite covers:

- strict configuration parsing, path resolution, and unsafe-setting rejection;
- identity reconstruction and signature validation;
- bounded MessagePack encoding and malformed-packet rejection;
- packet dispatch and Reticulum's `None`-on-success send contract;
- signed registration gossip with a destination distinct from its owner;
- invalid-signature rejection, rollback protection, and signed tombstones;
- global LRU cache eviction;
- private, atomically written persistence and verification on reload;
- authority-gated namespace creation, transfer, replay rejection, and deterministic transfer conflict resolution;
- label parsing and token-bucket behavior.

## Live two-node release smoke test

Automated tests isolate application logic from radio and interface behavior. Before deploying a new release to a real mesh, perform this short test with the exact Reticulum configuration and hardware used in production.

1. Create two Akita configuration files with the same `akita_namespace_identity_hash`, separate `storage_path` values, separate `persistence_path` values, short `gossip_interval`, and `peer_ttl` greater than the gossip interval.
2. Start one server with each configuration and confirm both log peer discovery.
3. Create a namespace with the network-authority identity, wait for gossip, and confirm `cli list --namespaces` shows the same owner on both nodes.
4. Register a name with the namespace owner identity. Resolve it through each node and compare the destination hash.
5. Update the name twice in the same second from the owner and confirm both nodes converge to the same deterministic value.
6. Revoke the name, wait for gossip, and confirm neither node resolves it. Restart one node and confirm the tombstone still blocks the older record.
7. Transfer the namespace from a client whose local persistence contains the ownership chain. Confirm both nodes remove records signed by the previous owner and reject new registrations from it.
8. Stop and restart both nodes. Confirm registry signatures and namespace chains load without warnings and non-expired records remain resolvable.
9. Send malformed, oversized, expired, future-dated, and invalid-signature packets from a test client. Confirm they are rejected without process termination or state changes.
10. Query `/healthz` and all dashboard read APIs. If HTTP mutation is enabled, verify missing and incorrect bearer tokens receive `401` and the correct token can register only names authorized for the server identity.
11. Send enough names to exercise `max_registry_size` and enough requests to trigger the rate limiter. Confirm the process remains responsive and logs bounded refusals.
12. Stop each process with both SIGTERM and SIGINT and confirm it exits cleanly without a temporary state file remaining.

## Release gate

A release passes when automated checks succeed in a clean environment, the built wheel contains `akita_ddns/static/index.html`, and the live smoke test succeeds on each production interface type. Preserve the command output and relevant server logs with the release artifacts.
