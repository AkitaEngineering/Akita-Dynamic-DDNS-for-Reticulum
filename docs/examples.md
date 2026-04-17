# Akita DDNS Usage Examples

This file provides more detailed examples of how to use the Akita DDNS server and command-line interface (CLI).

---

## Table of Contents
- [Prerequisites](#prerequisites)
- [1. Running the Server](#1-running-the-server)
- [2. Using the CLI](#2-using-the-cli)
  - [2.1. Registering a Name](#21-registering-a-name)
  - [2.2. Resolving a Name](#22-resolving-a-name)
  - [2.3. Creating a Namespace](#23-creating-a-namespace)
  - [2.4. Listing Local State](#24-listing-local-state)
- [3. Configuration (akita_config.yaml)](#3-configuration-akita_configyaml)

---

## Prerequisites

- Akita DDNS code cloned or installed.
- Dependencies installed (`pip install -r requirements.txt`).
- A valid `akita_config.yaml` file created in the execution directory, especially with the correct `akita_namespace_identity_hash`.
- Reticulum configured with at least one interface active.

---

## 1. Running the Server

<details>
<summary><strong>Click to expand instructions</strong></summary>

```bash
# Navigate to the directory containing the akita_ddns module
cd /path/to/akita-ddns

# Run the server module
python -m akita_ddns.main --config akita_config.yaml server
```
The server will initialize Reticulum, load persisted state when enabled, listen for Akita protocol packets, and start the periodic gossip and TTL maintenance loops.

Leave this running in its own terminal or as a background process.

</details>

## 2. Using the CLI

The CLI allows interaction with the Akita network, your server, and peers.

### 2.1. Registering a Name

<details>
<summary><strong>Click to expand name registration examples</strong></summary>

Using the default identity and namespace:

```bash
python -m akita_ddns.main --config akita_config.yaml cli register --name mycomputer
```

Specifying a namespace:

```bash
python -m akita_ddns.main --config akita_config.yaml cli register --name webserver.production
```

Using a specific identity file:

```bash
python -m akita_ddns.main --config akita_config.yaml cli register --name api.staging --identity ~/.config/reticulum/identities/service_id
```

Registering a different RID:

```bash
python -m akita_ddns.main --config akita_config.yaml cli register --name printer.office --rid fedcba987...
```

Specifying a time-to-live:

```bash
python -m akita_ddns.main --config akita_config.yaml cli register --name tempbox.lab --ttl 3600
```

</details>

### 2.2. Resolving a Name

<details>
<summary><strong>Click to expand name resolution examples</strong></summary>

Resolving in the default namespace:

```bash
python -m akita_ddns.main --config akita_config.yaml cli resolve --name mycomputer
```

Resolving in a specific namespace:

```bash
python -m akita_ddns.main --config akita_config.yaml cli resolve --name webserver.production
```

Adjusting timeout:

```bash
python -m akita_ddns.main --config akita_config.yaml cli resolve --name far-away-node.remote --timeout 10
```

</details>

### 2.3. Creating a Namespace

<details>
<summary><strong>Click to expand namespace creation examples</strong></summary>

Using the default identity:

```bash
python -m akita_ddns.main --config akita_config.yaml cli create_namespace --namespace home
```

Using a specific owner identity:

```bash
python -m akita_ddns.main --config akita_config.yaml cli create_namespace --namespace secure --owner_identity ~/.config/reticulum/identities/admin_id
```

</details>

### 2.4. Listing Local State

<details>
<summary><strong>Click to expand state listing examples</strong></summary>

```bash
# List persisted registry entries
python -m akita_ddns.main --config akita_config.yaml cli list --registry

# List persisted namespace ownership
python -m akita_ddns.main --config akita_config.yaml cli list --namespaces

# List persisted reputation scores
python -m akita_ddns.main --config akita_config.yaml cli list --reputation

# List multiple states
python -m akita_ddns.main --config akita_config.yaml cli list --registry --namespaces
```

Listing the cache is not supported because the cache is in-memory only.

</details>

## 3. Configuration (`akita_config.yaml`)

<details>
<summary><strong>Click to expand key configuration fields</strong></summary>

Ensure `akita_config.yaml` is present where you run Akita DDNS, or pass an explicit path with `--config`.

Key fields:

- `akita_namespace_identity_hash`: Crucial for consistency across nodes.

- `persist_state`: Set to `true` to save registry, namespaces, and reputation across restarts.

- `persistence_path`: Directory where state files are stored if persistence is enabled.

Refer to the main README.md or example config file for a full list of options.

</details>
