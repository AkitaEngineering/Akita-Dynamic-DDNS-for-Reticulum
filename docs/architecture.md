# Architecture

## Process layout

`akita_ddns.main` loads and validates configuration, initializes Reticulum, loads the persisted node identity, starts the protocol server, and optionally starts the HTTP dashboard. The server owns two cancellable background tasks: gossip and TTL/cache maintenance. Signal-driven shutdown disables packet callbacks, unregisters the announce handler, cancels both tasks, and cleans up the HTTP runner.

The CLI uses the same configuration and identity storage. The `list` command intentionally avoids starting Reticulum, which makes local diagnostics usable even when no interface is available.

## Reticulum destinations

Every destination includes the configured network ID as an aspect. This prevents unrelated Akita networks from sharing the same destination hashes.

- `akita_ddns.<network-id>.broadcast`: one-hop `PLAIN` broadcast destination for client mutations and resolution requests.
- `akita_ddns.<network-id>.node.<identity>`: announced `SINGLE` destination for peer gossip.
- `akita_ddns.<network-id>.response.<identity>`: client `SINGLE` destination for resolution responses.

Peers are learned from authenticated Reticulum announces, refreshed during gossip cycles, and removed after `peer_ttl`.

Reticulum does not forward `PLAIN` data beyond one hop. A CLI therefore sends to Akita servers on its local/shared Reticulum instance or directly attached interface. Servers use routed `SINGLE` destinations for peer gossip, so an accepted event can cross the multi-hop network even though its client ingress packet cannot. Deploy an Akita server at every client ingress point.

## Wire protocol

`protocol.py` encodes a compact MessagePack array containing a protocol version, numeric command, and command fields. Decoding limits the packet and collection sizes. Encoding rejects any message larger than `RNS.Packet.MDU`.

Registration signatures cover the namespace, name, destination hash, TTL, and timestamp in a canonical MessagePack representation. The public key carried with a record reconstructs the signer identity. Namespace ownership is checked after signature validation.

Resolution requests contain the requester's public key and a cryptographically random nonce. A server returns the complete signed registry entry to the requester's `SINGLE` destination. The client validates the nonce, fields, lifetime, signature, and any locally known namespace owner before accepting the destination hash.

## Registry and revocation

The in-memory registry is guarded by a re-entrant lock and capped by `max_registry_size`. Newer timestamps win. When timestamps are equal, a stable tuple ordering makes all peers choose the same record.

A revocation is a signed registration with an empty destination hash and a TTL equal to `max_registration_ttl`. It is not returned by resolution, but it is persisted and gossiped until all records it supersedes must have expired. This prevents delayed gossip from restoring the revoked value.

Gossip sends one signed registry or namespace event per Reticulum packet. `max_gossip_entries_per_cycle` bounds work and traffic; a rotating cursor ensures larger registries are covered across cycles.

## Namespace ownership

A namespace record contains a signed create event followed by signed, sequenced transfer events. A create event is accepted only when signed by the identity whose hash is `akita_namespace_identity_hash`; this provides a stable trust root and prevents arbitrary identities from racing or grinding namespace claims. Each transfer signs the namespace, new owner, sequence, timestamp, and random transfer ID.

If the same owner signs competing transfers at one sequence, the lower transfer ID wins and later events on the losing branch are discarded. This rule provides arrival-order-independent convergence after the authority creates a namespace.

When ownership changes, registry entries not signed by the new owner are removed and cached values for that namespace are invalidated. Ownership chains are persisted and replay-verified at startup. Legacy owner-only records have no proof chain and are ignored.

Unclaimed namespaces are closed by default. `allow_unowned_namespaces: true` enables open namespaces, where any identity can overwrite a name with a newer signed record; this mode does not provide name ownership and is intended only for explicitly trusted meshes.

## Persistence

Registry, namespace, and reputation state use YAML only on local disk; YAML is not used on the network. Reads use `safe_load`, reject oversized files, validate structure, and cryptographically recheck signed records. Writes use `safe_dump`, mode `0600`, `fsync`, atomic replacement, and directory synchronization where the filesystem supports it.

The resolution cache is a process-wide bounded LRU. Registry lookup itself is constant-time; the cache exists for consumers that use it, and mutation handlers explicitly invalidate affected entries.

## HTTP dashboard

The aiohttp dashboard uses snapshot methods instead of reaching into component internals. Request bodies are bounded, errors do not expose exception details, and browser security headers are applied to responses. Data is rendered with DOM `textContent`, preventing registry values from becoming HTML.

Read endpoints are enabled with the dashboard. Registration mutation is absent unless explicitly enabled and protected by a constant-time bearer-token comparison.
