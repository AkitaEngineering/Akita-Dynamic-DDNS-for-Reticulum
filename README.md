# Akita Dynamic DDNS for Reticulum

Akita is a distributed, dynamic destination naming system (DDNS) designed for the Reticulum network. It provides a robust and decentralized way to associate human-readable names with dynamic Reticulum identities (RIDs).

## Features

-   **Distributed Registry:** Utilizes Reticulum's mesh networking for a resilient, decentralized registry.
-   **Dynamic Updates:** Allows devices to dynamically update their names when their RIDs change.
-   **Name Resolution:** Resolves human-readable names to RIDs through the Reticulum network.
-   **Namespace Management:** Organizes names with namespaces, preventing collisions.
-   **Security and Authentication:** Uses Reticulum's cryptography for secure updates and queries.
-   **Extensible Design:** Designed to be easily extended with new features.
-   **Gossip Protocol:** Implements a gossip protocol for efficient registry propagation.
-   **Rate Limiting:** Protects against abuse with request rate limiting.
-   **Namespace Ownership:** Allows namespace creation and ownership management.
-   **Reputation System:** Maintains node reputation for reliable service.
-   **CLI Interface:** Provides a command-line interface for easy management.
-   **Configuration File:** Uses a YAML configuration file for easy customization.

## Requirements

-   Python 3.6+
-   Reticulum

## Installation

1.  Clone the repository:

    ```bash
    git clone [repository_url]
    cd [repository_directory]
    ```

2.  Install Reticulum (if not already installed):

    ```bash
    pip install reticulum
    ```

3.  Create or modify the `akita_config.yaml` file to your liking. An example file will be created if one does not exist.

## Usage

1.  **Run Akita:**

    ```bash
    python akita_ddns.py
    ```

    (Replace `akita_ddns.py` with the filename you chose.)

2.  **Use the CLI:**

    ```bash
    python akita_ddns.py <command> [options]
    ```

    **Commands:**

    -   `register`: Register a name.
    -   `resolve`: Resolve a name.
    -   `create_namespace`: Create a namespace.

    **Options:**

    -   `--name`: Name to register or resolve.
    -   `--namespace`: Namespace (default: Akita namespace).
    -   `--rid`: RID to register.
    -   `--owner`: Owner RID for namespace creation.

    **Example:**

    ```bash
    python akita_ddns.py register --name my-device.home --rid abc123def456
    python akita_ddns.py resolve --name my-device.home
    python akita_ddns.py create_namespace --namespace my_namespace --owner owner_rid
    ```

## Configuration (`akita_config.yaml`)

-   `akita_namespace`: Unique namespace for Akita.
-   `akita_port`: Port for Akita service.
-   `update_interval`: Interval for name updates (seconds).
-   `cache_ttl`: Cache time-to-live (seconds).
-   `log_level`: Logging level (e.g., INFO, DEBUG).
-   `max_cache_size`: Maximum cache size.
-   `gossip_interval`: Gossip interval (seconds).
-   `ttl_interval`: TTL check interval (seconds).
-   `default_ttl`: Default TTL for registrations (seconds).
-   `gossip_neighbors`: Number of gossip neighbors.
-   `rate_limit`: Requests per second limit.
-   `namespace_owners`: Dictionary of namespace owners.
-   `reputation`: Dictionary of node reputations.

## Contributing

Contributions are welcome! Please submit pull requests or open issues for bug reports and feature requests.
