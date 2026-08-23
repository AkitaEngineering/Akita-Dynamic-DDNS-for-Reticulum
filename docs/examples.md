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
  - [2.4. Creating and Managing Namespaces](#24-creating-and-managing-namespaces)
  - [2.5. Listing Local State](#25-listing-local-state)
- [3. Configuration (akita_config.yaml)](#3-configuration-akita_configyaml)

---

## Prerequisites

- Akita DDNS code cloned or installed.
- Dependencies installed (`pip install -r requirements.txt`).
- A valid `akita_config.yaml` file created in the execution directory, especially with the correct `akita_namespace_identity_hash`.
- A namespace created by the network-authority identity. Unclaimed namespaces reject registrations by default.
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
The server will initialize Reticulum, load persisted state when enabled, start the Web UI dashboard on `127.0.0.1:48080`, listen for Akita protocol packets, and start the periodic gossip and TTL maintenance loops.

Leave this running in its own terminal or as a background process.

You can view the real-time node state by visiting `http://127.0.0.1:48080` in your browser.

</details>

## 2. Using the CLI

The CLI allows interaction with the Akita network, your server, and peers.

Reticulum client requests use one-hop `PLAIN` broadcasts. Run the CLI with a local/shared Reticulum instance that also hosts an Akita server, or from a directly connected Reticulum interface. Akita servers relay accepted changes to remote peers with routed gossip.

### 2.1. Registering a Name

<details>
<summary><strong>Click to expand name registration examples</strong></summary>

Using a claimed namespace and its owner identity:

```bash
python -m akita_ddns.main --config akita_config.yaml cli register --name mycomputer.home --identity ./akita-network-authority
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
python -m akita_ddns.main --config akita_config.yaml cli register --name printer.office --rid fedcba9876543210fedcba9876543210
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

Watching a name continuously for changes:

```bash
python -m akita_ddns.main --config akita_config.yaml cli watch --name far-away-node.remote --interval 5
```

</details>

### 2.3. Revoking a Name

<details>
<summary><strong>Click to expand name revocation examples</strong></summary>

You can revoke a name by publishing a signed tombstone. Peers retain and gossip the tombstone for `max_registration_ttl`, so delayed records cannot restore the name.

```bash
python -m akita_ddns.main --config akita_config.yaml cli revoke --name mycomputer
```

</details>

### 2.4. Creating and Managing Namespaces

<details>
<summary><strong>Click to expand namespace creation examples</strong></summary>

Using the retained network-authority identity:

```bash
python -m akita_ddns.main --config akita_config.yaml cli create_namespace --namespace home --owner_identity ./akita-network-authority
```

The namespace creator must be the authority identity whose hash is configured as `akita_namespace_identity_hash`:

```bash
python -m akita_ddns.main --config akita_config.yaml cli create_namespace --namespace secure --owner_identity ./akita-network-authority
```

Transferring namespace ownership to a new Identity Hash:

```bash
python -m akita_ddns.main --config akita_config.yaml cli transfer_namespace --namespace secure --new_owner 4d284af075e26513f733c1f4d738b224
```

The transferring client's configured persistence directory must already contain the namespace ownership chain. This supplies the signed transfer sequence and prevents replay or branching ambiguity.

</details>

### 2.5. Listing Local State

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

- `akita_namespace_identity_hash`: Network-isolation aspect and namespace-authority identity hash shared by all participating nodes. A null value uses the local node identity and is therefore only suitable for one node.

- `persist_state`: Set to `true` to save registry, namespaces, and reputation across restarts.

- `persistence_path`: Directory where state files are stored if persistence is enabled.

- `max_registration_ttl`, `max_clock_skew`, `max_registry_size`, and `max_namespaces`: Protocol and resource limits.

- `allow_unowned_namespaces`: Defaults to `false`. Enabling it permits any identity to update names in namespaces that have not been claimed.

- `web_ui_allow_mutations` and `web_ui_api_token`: Registration API control. A token of at least 32 characters is mandatory when mutation is enabled.

Refer to the main README.md or example config file for a full list of options.

</details>
