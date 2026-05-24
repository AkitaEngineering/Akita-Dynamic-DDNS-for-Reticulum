# Akita DDNS Architecture Overview

This document provides a high-level overview of the modular architecture of the Akita DDNS project.

---

## Table of Contents
- [Core Concepts](#core-concepts)
- [Module Breakdown](#module-breakdown)
  - [main.py](#mainpy)
  - [config.py](#configpy)
  - [storage.py](#storagepy)
  - [crypto.py](#cryptopy)
  - [namespace.py](#namespacepy)
  - [reputation.py](#reputationpy)
  - [network.py](#networkpy)
  - [cli.py](#clipy)
  - [utils.py](#utilspy)
- [Data Flow Examples](#data-flow-examples)
  - [Registration](#registration)
  - [Resolution](#resolution)
  - [Gossip](#gossip)

---

## Core Concepts

- **Decentralized:** Relies on Reticulum's mesh networking; no central servers.
- **Gossip Protocol:** Nodes share their known registry information with peers for eventual consistency.
- **Cryptographic Identity:** Uses Reticulum identities for signing registrations and verifying ownership.
- **Namespaces:** Organizes names to prevent collisions and control ownership.
- **TTL (Time-to-Live):** Registrations expire automatically unless periodically updated.
- **Persistence:** Optionally saves state locally to survive restarts.
- **Reputation:** Basic system to track peer behavior (optional).

---

## Module Breakdown

The codebase is organized into several Python modules inside the `akita_ddns` package.

---

### main.py

<details>
<summary><strong>Click to expand</strong></summary>

- Entry point for server and CLI modes.
- Parses top-level arguments and dispatches to server or CLI.
- Initializes Reticulum.
- Sets up signal handling for graceful shutdown (server mode).
- Orchestrates server components or CLI commands.

</details>

---

### config.py

<details>
<summary><strong>Click to expand</strong></summary>

- Defines default configuration values.
- Loads configuration from `akita_config.yaml`.
- Validates configuration settings.
- Caches the most recently loaded config by path to avoid mixing settings from different config files in the same process.
- Provides access to the global configuration dictionary.

</details>

---

### storage.py

<details>
<summary><strong>Click to expand</strong></summary>

- **PersistentStorage:** Saves and loads state (registry, namespaces, reputation) via YAML files with atomic writes.
- **Registry:** 
  - Manages the DDNS in-memory registry (name -> RID mappings).
  - Handles TTLs, gossip updates, and local resolutions.
  - Works with PersistentStorage for persistence.
- **Cache:** 
  - Maintains an in-memory cache of resolved names.
  - Includes TTL expiry logic for cache entries.

</details>

---

### crypto.py

<details>
<summary><strong>Click to expand</strong></summary>

- Provides wrappers around Reticulum identity signing and verification.
- Reconstructs Reticulum identities from embedded public keys for signature checks.
- Functions for generating and verifying digital signatures.

</details>

---

### namespace.py

<details>
<summary><strong>Click to expand</strong></summary>

- **NamespaceManager:**
  - Manages namespace ownership.
  - Verifies authority for registrations in namespaces.
  - Persists namespace data via PersistentStorage.

</details>

---

### reputation.py

<details>
<summary><strong>Click to expand</strong></summary>

- **ReputationManager:**
  - Manages peer reputation scores based on behavior.
  - Observes valid signatures, successful resolutions, etc.
  - Persists reputation data via PersistentStorage.

</details>

---

### network.py

<details>
<summary><strong>Click to expand</strong></summary>

- **Client Anycast Listener:** 
  - Listens for incoming Reticulum packets on an un-identified `PLAIN` Akita destination. This allows local CLI clients to reach the nearest running Akita node automatically.
- **Node-Specific Listener & P2P Gossip:**
  - Nodes discover each other via Reticulum Announces and maintain a list of known peers.
  - Nodes gossip updates by sending direct `SINGLE` packets to known peers.
  - Verifies message authenticity from signed payload data and embedded public keys.
  - Sends and receives protocol messages.
  - Runs background tasks like gossiping the registry and TTL checks.

</details>

---

### cli.py

<details>
<summary><strong>Click to expand</strong></summary>

- Defines CLI structure with `argparse`.
- Implements commands: `register`, `resolve`, `create_namespace`, `list`.
- Uses network helpers to send/receive Akita protocol messages.
- Loads local state directly for `list` operations.

</details>

---

### utils.py

<details>
<summary><strong>Click to expand</strong></summary>

- Provides miscellaneous utilities:
  - **RateLimiter:** Limits incoming request rates.
  - **build_registration_payload:** Builds the signed registration payload used by CLI, server helpers, and gossip verification.
  - **parse_name:** Helper for parsing fully qualified names into name/namespace parts.

</details>

---

## Data Flow Examples

---

### Registration

<details>
<summary><strong>Click to expand</strong></summary>

1. CLI uses `ret.Packet` to send the payload to the Anycast destination (`APP_NAME, "broadcast"`).
2. Reticulum routes this to the nearest active `AkitaServer` node.
3. Node receives `REGISTER` packet.
4. Rate limit checked (`utils.RateLimiter`).
5. Packet parsed and signature verified from the embedded public key.
6. Namespace ownership verified against the signer identity (`namespace.NamespaceManager.is_authorized`).
7. Entry added or updated in `storage.Registry`.
8. State persisted via `PersistentStorage.save_registry()`.
9. Reputation updated (`reputation.ReputationManager.update_reputation`).

</details>

---

### Resolution

<details>
<summary><strong>Click to expand</strong></summary>

1. CLI asks for resolution of `myname.mynamespace`.
2. CLI sends `RESOLVE` packet to the Anycast destination.
3. Nearest Node receives `RESOLVE` packet.
4. Rate limit checked.
5. Packet parsed.
6. Check `storage.Cache` for result.
7. If not cached or expired:
   - Check `storage.Registry.resolve()`.
   - If found, update cache (`storage.Cache.put()`).
8. Server sends `RESPONSE` packet back to requester's destination.
9. CLI/Client's `_cli_response_callback()` processes the response.

</details>

---

### Gossip

<details>
<summary><strong>Click to expand</strong></summary>

1. Server's `AkitaServer.run_gossip_loop()` periodically triggers.
2. Gets valid registry entries via `Registry.get_registry_for_gossip()`.
3. `network.py` serializes the dictionary to YAML.
4. Sends `GOSSIP` packets directly to all discovered peer nodes.
5. Receiving server handles packet:
   - Parses YAML.
   - Converts hex back to bytes.
   - Passes to `Registry.process_gossip()`.
6. Verifies entries, timestamps, signatures, and namespace-owner identity.
7. Updates local registry if necessary.
8. Leaves reputation updates to validated registration and namespace-owner events.

</details>

---
