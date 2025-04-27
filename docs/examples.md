Akita DDNS Usage ExamplesThis file provides more detailed examples of how to use the Akita DDNS server and command-line interface (CLI).Prerequisites:Akita DDNS code cloned or installed.Dependencies installed (pip install -r requirements.txt).A valid akita_config.yaml file created in the execution directory, especially with the correct akita_namespace_identity_hash set for your desired network.Reticulum configured with at least one interface active.1. Running the ServerTo participate in the Akita DDNS network, resolve names, and serve your own registered names, you need to run the server node.# Navigate to the directory containing the akita_ddns module
# (usually the root of the cloned repository)
cd /path/to/akita-ddns

# Ensure akita_config.yaml is present here

# Run the server module
python -m akita_ddns.main server
The server will start, initialize Reticulum, load state (if persist_state is true), listen for incoming requests on the configured UDP port, and start background tasks for gossip and TTL checks. Leave this running in its own terminal or as a background process/service.2. Using the CLIThe CLI interacts with the Akita network (including your running server or other peers).2.1. Registering a NameThis associates a name within a namespace to your node's Reticulum Identity hash (or a specified RID).Using Default Identity and Default Namespace:If akita_namespace_identity_hash in your config is abcdef123..., this registers mycomputer within that default namespace.python -m akita_ddns.main cli register --name mycomputer
Specifying a Namespace:This registers webserver within the production namespace. The production namespace must either not be owned, or the identity used must be the owner.python -m akita_ddns.main cli register --name webserver.production
Using a Specific Identity File:This uses the identity stored in ~/.config/reticulum/identities/service_id to sign the registration for api.staging.python -m akita_ddns.main cli register --name api.staging --identity ~/.config/reticulum/identities/service_id
Registering a Different RID:This registers the name printer.office to point to the RID fedcba987..., signed using your default identity. Useful if managing records for devices that can't run Akita themselves.python -m akita_ddns.main cli register --name printer.office --rid fedcba987...
Specifying Time-to-Live (TTL):Register tempbox.lab with a short TTL of 1 hour (3600 seconds).python -m akita_ddns.main cli register --name tempbox.lab --ttl 3600
2.2. Resolving a NameThis looks up the RID associated with a name.Resolving in Default Namespace:python -m akita_ddns.main cli resolve --name mycomputer
Resolving in a Specific Namespace:python -m akita_ddns.main cli resolve --name webserver.production
Adjusting Timeout:Wait up to 10 seconds for a response.python -m akita_ddns.main cli resolve --name far-away-node.remote --timeout 10
2.3. Creating a NamespaceThis registers ownership of a namespace to a specific identity, preventing others from registering names within it unless they are the owner.Using Default Identity:Creates the home namespace, owned by your default Reticulum identity.python -m akita_ddns.main cli create_namespace --namespace home
Using a Specific Owner Identity:Creates the secure namespace, owned by the identity in admin_id.python -m akita_ddns.main cli create_namespace --namespace secure --owner_identity ~/.config/reticulum/identities/admin_id
2.4. Listing Local StateThis command displays the contents of the local node's persisted state files for debugging (requires persist_state: true in config).# List persisted registry entries
python -m akita_ddns.main cli list --registry

# List persisted namespace ownership
python -m akita_ddns.main cli list --namespaces

# List persisted reputation scores
python -m akita_ddns.main cli list --reputation

# List multiple states
python -m akita_ddns.main cli list --registry --namespaces
(Note: Listing the cache is not supported as it's in-memory only)3. Configuration (akita_config.yaml)Ensure this file is present in the directory where you run python -m akita_ddns.main ....Key fields:akita_namespace_identity_hash: Crucial. Must be the same for all nodes in the same DDNS system.persist_state: Set to true to save registry/namespaces/reputation across restarts.persistence_path: Where state files are stored if persist_state is true.Refer to the main README.md or the example config file for a full list of configuration options.aces/reputation across restarts.persistence_path: Where state files are stored if persist_state is true.Refer to the main README.md or the example config file for a full list of configuration options.
