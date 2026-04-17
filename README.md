# Akita DDNS - Distributed DNS for RNS (Reticulum)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

**Developed by Akita Engineering (https://www.akitaengineering.com)**

Akita DDNS is a robust, decentralized, and dynamic destination naming system (DDNS) built on the Reticulum Network Stack (imported in code as `RNS`). It provides a resilient alternative to traditional centralized DNS for mapping human-readable names to dynamic Reticulum identities (RIDs) within a mesh network.

Akita DDNS uses RNS identities and application destinations to sign and distribute name registrations, and a lightweight gossip protocol to propagate registry entries across peers.

## Features

* **Decentralized Registry:** No single point of failure. Registry data is distributed across participating nodes via a gossip protocol.
* **Cryptographically Secure:** Utilizes Reticulum's identity-based signatures for authenticating registrations, updates, and namespace control.
* **Dynamic Updates:** Nodes can automatically update their associated RIDs when they change.
* **Namespace Management:** Organize names into namespaces to prevent collisions. Supports cryptographic ownership of namespaces.
* **Resilient:** Designed to operate effectively over Reticulum's potentially low-bandwidth, high-latency mesh links.
* **TTL (Time-to-Live):** Registrations automatically expire, ensuring stale entries are eventually removed.
* **Persistence:** Optionally saves state (registry, namespaces, reputation) locally to survive restarts.
* **Rate Limiting:** Basic protection against request flooding.
* **Reputation System:** Optional tracking of peer behavior to potentially prioritize reliable nodes (future enhancement).
* **Modular Codebase:** Organized Python package for maintainability and extensibility.
* **CLI Interface:** Command-line tool for easy interaction (register, resolve, manage namespaces, inspect local state).


## Requirements
- Python 3.7+

See `requirements.txt` for specific Python package dependencies (`rns`, `pyyaml`, `pytest`).

---

## Installation
Clone the repository:

    git clone https://github.com/AkitaEngineering/Akita-Dynamic-DDNS-for-Reticulum 
    cd akita-ddns # Or your chosen directory name

Install dependencies (recommended inside a virtualenv):

    python -m venv .venv
    .venv\Scripts\activate    # Windows
    source .venv/bin/activate  # macOS / Linux
    pip install -r requirements.txt

Configure: Create `akita_config.yaml` in the project root (see `akita_config.yaml (Example)`).

Important:
- `akita_namespace_identity_hash` identifies the shared Akita network. You can either paste a pre-generated hash or let the project create and store an identity. Example generation (uses `RNS`):

    python -c "import RNS as ret; print(ret.Identity().hash.hex())"

By default the node will create an identity file under the configured `storage_path` if none is present.

---

## Usage
See `docs/examples.md` for detailed usage examples.

### 1. Run the Server Node:

Ensure `akita_config.yaml` is present (or pass `--config <path>`). Then run:

```bash
# start server (uses config path if provided)
python -m akita_ddns.main --config akita_config.yaml server
```

The server will initialize RNS, create/load an identity (if needed), listen for incoming messages, gossip registry entries, and perform periodic TTL checks.

### 2. Use the CLI:

The CLI is part of the same module and uses the local RNS instance and stored identity. Examples:

```bash
# Register (uses default identity under storage_path)
python -m akita_ddns.main --config akita_config.yaml cli register --name mynode

# Resolve with a timeout
python -m akita_ddns.main --config akita_config.yaml cli resolve --name mynode --timeout 5

# Create a namespace (signed by identity)
python -m akita_ddns.main --config akita_config.yaml cli create_namespace --namespace home

# Show persisted state (if persistence enabled)
python -m akita_ddns.main --config akita_config.yaml cli list --registry --namespaces --reputation
```

Use:
    python -m akita_ddns.main --config akita_config.yaml cli <command> --help

for command-specific options.

---

## Testing

Run the test suite with:

    pytest tests/

Current automated coverage includes configuration loading, Reticulum public-key signature verification, packet dispatch behavior, gossip ownership checks, and utility helpers.

See `docs/testing.md` for the current testing scope and manual multi-node validation guidance.

---

## Configuration (`akita_config.yaml`)

This file controls Akita's behavior. Key settings include:

- `akita_namespace_identity_hash`: Shared hash defining your Akita network. If omitted the node will create/store an identity and use its hash.
- `persist_state`: Enable/disable saving state to disk.
- `persistence_path`: Directory for state files.
- Timing intervals (`gossip_interval`, `ttl_check_interval`, etc.).
- Logging level (`log_level`).

Refer to the example `akita_config.yaml` for all options and detailed comments.

---

## License
This project is licensed under the **GNU General Public License v3.0**. See the `LICENSE` file for details.

---

## Contributing

Contributions are welcome. Please follow standard GitHub workflow:

- Fork the repository
- Create a feature branch
- Add tests where appropriate
- Submit a PR with a clear description

See `docs/testing.md` for testing instructions.

---

**Akita Engineering** — Building resilient communication systems.  
[www.akitaengineering.com](http://www.akitaengineering.com)
