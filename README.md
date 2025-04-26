Akita DDNS - Distributed DNS for ReticulumDeveloped by Akita Engineering (www.akitaengineering.com)Akita DDNS is a robust, decentralized, and dynamic destination naming system (DDNS) built specifically for the Reticulum Network Stack. It provides a resilient alternative to traditional centralized DNS for mapping human-readable names to dynamic Reticulum identities (RIDs) within a mesh network.Leveraging Reticulum's inherent cryptography and peer-to-peer communication, Akita DDNS offers a secure and censorship-resistant way to manage names in environments where central authorities are undesirable or unavailable.FeaturesDecentralized Registry: No single point of failure. Registry data is distributed across participating nodes via a gossip protocol.Cryptographically Secure: Utilizes Reticulum's identity-based signatures for authenticating registrations, updates, and namespace control.Dynamic Updates: Nodes can automatically update their associated RIDs when they change.Namespace Management: Organize names into namespaces to prevent collisions. Supports cryptographic ownership of namespaces.Resilient: Designed to operate effectively over Reticulum's potentially low-bandwidth, high-latency mesh links.TTL (Time-to-Live): Registrations automatically expire, ensuring stale entries are eventually removed.Persistence: Optionally saves state (registry, namespaces, reputation) locally to survive restarts.Rate Limiting: Basic protection against request flooding.Reputation System: Optional tracking of peer behavior to potentially prioritize reliable nodes (future enhancement).Modular Codebase: Organized Python package for maintainability and extensibility.CLI Interface: Command-line tool for easy interaction (register, resolve, manage namespaces, inspect local state).Project Structureakita_ddns/
├── __init__.py
├── cli.py              # Command Line Interface logic
├── config.py           # Configuration loading and management
├── crypto.py           # Cryptographic functions (signing, verification)
├── main.py             # Main entry point (server startup, CLI dispatch)
├── namespace.py        # Namespace management logic
├── network.py          # Reticulum network interactions (server, gossip)
├── reputation.py       # Reputation system logic
├── storage.py          # Registry and Cache management (including TTL & persistence)
└── utils.py            # Utility functions (e.g., rate limiting)
akita_config.yaml       # Configuration file (REQUIRED)
README.md               # This file
requirements.txt        # Project dependencies
docs/
├── examples.md         # Detailed usage examples
├── architecture.md     # Overview of the code structure
└── testing.md          # Guide on how to test the application
RequirementsPython 3.7+See requirements.txt for specific Python package dependencies (reticulum, pyyaml).InstallationClone the repository:git clone [repository_url] # Replace with actual URL
cd akita-ddns # Or your chosen directory name
Install dependencies:pip install -r requirements.txt
Configure: Create akita_config.yaml in the project root. Crucially, set akita_namespace_identity_hash to a unique, shared hash for all nodes participating in your Akita DDNS network. Refer to the example config file for details.UsageSee docs/examples.md for detailed usage examples.1. Run the Server Node:# Ensure akita_config.yaml is present
python -m akita_ddns.main server
This node will listen, gossip, and serve requests.2. Use the CLI:# Register a name (using default identity and default namespace)
python -m akita_ddns.main cli register --name mynode

# Resolve a name
python -m akita_ddns.main cli resolve --name mynode

# Create a namespace (owned by default identity)
python -m akita_ddns.main cli create_namespace --namespace home

# List local persisted state (if enabled)
python -m akita_ddns.main cli list --registry --namespaces
Use python -m akita_ddns.main cli <command> --help for command-specific options.Configuration (akita_config.yaml)This file controls Akita's behavior. Key settings include:akita_namespace_identity_hash: Mandatory shared hash defining your network.persist_state: Enable/disable saving state to disk.persistence_path: Directory for state files.Timing intervals (gossip_interval, ttl_check_interval, etc.).Logging level (log_level).Refer to the example akita_config.yaml for all options and detailed comments.LicenseThis project is licensed under the GNU General Public License v3.0. See the LICENSE file for details.ContributingContributions are welcome! Please refer to docs/testing.md for testing information. Submit pull requests or open issues on the project repository.Akita Engineering - Building resilient communication systems.www.akitaengineering.com.


