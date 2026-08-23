# Akita DDNS

Akita DDNS is a signed, distributed destination-name registry for the Reticulum Network Stack. It maps human-readable `name.namespace` values to Reticulum destination hashes and propagates records between Akita peers with bounded gossip packets.

## Security and reliability properties

- Registrations, revocations, namespace claims, and namespace transfers are signed by Reticulum identities.
- Each wire message uses a versioned MessagePack schema and is checked against Reticulum's packet MDU before transmission.
- Resolution requests use a random nonce and a `SINGLE` response destination. Clients verify the returned registration signature and TTL.
- Revocations are signed tombstones retained for the maximum registration TTL, preventing stale gossip from resurrecting a deleted record.
- Namespace creation is authorized by the identity whose hash is the configured network ID. Same-sequence transfers have deterministic winners so peers converge regardless of arrival order.
- Unclaimed namespaces reject registrations by default. Operators can explicitly opt into open, first-writer-unprotected namespaces with `allow_unowned_namespaces`.
- Timestamps, TTLs, labels, hashes, public keys, signatures, registry size, namespace count, state-file size, and HTTP request size are bounded.
- State writes use private permissions, a temporary file, `fsync`, atomic replacement, and directory synchronization where supported.
- Persisted registry and namespace records are cryptographically revalidated when loaded.
- The dashboard escapes untrusted data, sends restrictive browser security headers, and disables mutation by default.

Akita provides integrity and namespace authorization, not traffic anonymity. Client requests travel to a Reticulum `PLAIN` broadcast destination; signed records and public keys are therefore observable on the directly attached Reticulum segment. Reticulum accepts `PLAIN` data only through one network hop, so every CLI client must have an Akita server on its local/shared Reticulum instance or directly reachable interface. After a server accepts an event, Akita propagates it between servers through routed `SINGLE` destinations. Resolution responses also use routed `SINGLE` destinations.

## Requirements

- Python 3.10 or newer
- Reticulum 1.x with at least one configured interface

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

For development and verification:

```bash
python -m pip install -r requirements-dev.txt
```

Copy `akita_config.yaml (Example)` to `akita_config.yaml` and review every setting. Multi-node deployments must set the same 32-character `akita_namespace_identity_hash` on every participating node. That hash is also the namespace-creation authority, so retain its identity file securely. When the field is `null`, Akita uses the local persisted node identity hash; that mode is suitable only for a local or single-node deployment.

Relative storage paths are resolved from the configuration file's directory, not from the process working directory. Unknown or unsafe configuration values stop startup instead of silently falling back.

## Run

After installation, either use the console command or `python -m akita_ddns.main`:

```bash
akita-ddns --config akita_config.yaml server

akita-ddns --config akita_config.yaml cli create_namespace --namespace home --owner_identity ./akita-network-authority
akita-ddns --config akita_config.yaml cli register --name router.home
akita-ddns --config akita_config.yaml cli resolve --name router.home --timeout 5
akita-ddns --config akita_config.yaml cli watch --name router.home --interval 10
akita-ddns --config akita_config.yaml cli revoke --name router.home
akita-ddns --config akita_config.yaml cli list --registry --namespaces --reputation
```

Namespace transfers require the ownership chain to be present in the client's configured local state:

```bash
akita-ddns --config akita_config.yaml cli transfer_namespace \
  --namespace home \
  --new_owner 0123456789abcdef0123456789abcdef
```

Names and namespaces are 1–63 ASCII letters, digits, underscores, or hyphens and must begin with a letter or digit. A fully qualified name contains one dot: `name.namespace`.

With the production default `allow_unowned_namespaces: false`, claim a namespace before registering in it. After a transfer, registrations must be signed by the current owner identity.

The CLI verifies protected resolution responses against the ownership chain in its configured persistence directory. Run CLI operations against a local synchronized Akita node's configuration, or copy the verified namespace state securely before resolving from a separate client host.

Client requests are intentionally one-hop Reticulum broadcasts. Deploy at least one Akita server at each client ingress point; server-to-server gossip carries accepted changes across the wider multi-hop network.

## Dashboard and HTTP API

The default dashboard listens only on `127.0.0.1:48080`.

- `GET /healthz`
- `GET /api/registry`
- `GET /api/namespaces`
- `GET /api/reputation`
- `POST /api/resolve`

`POST /api/register` is registered only when `web_ui_allow_mutations: true`. Enabling it also requires a token of at least 32 characters, supplied by `AKITA_WEB_UI_API_TOKEN` or `web_ui_api_token`. The environment variable takes precedence and avoids storing the secret in YAML. Send it as `Authorization: Bearer <token>`. If the dashboard is exposed beyond loopback, put it behind an authenticated TLS reverse proxy and restrict network access.

## Operations

- Back up the configured persistence directory and the `akita_identity` file together. The identity file is the signing authority.
- Keep clocks within `max_clock_skew`; badly skewed future registrations and transfers are rejected.
- Set `default_ttl` below or equal to `max_registration_ttl` and refresh registrations before they expire.
- The health endpoint proves the HTTP event loop is serving. Production supervision should also watch process exit status and logs.
- Upgrading from the pre-1.0 text/YAML wire protocol is intentionally incompatible. Upgrade all peers together. Unverifiable legacy namespace state is ignored; recreate namespace claims with the configured network-authority identity.

## Verify

```bash
pytest -q
python -m compileall -q akita_ddns tests
mypy akita_ddns
ruff check akita_ddns tests
ruff format --check akita_ddns tests
python -m build
```

See [usage examples](docs/examples.md), [architecture](docs/architecture.md), and [testing guidance](docs/testing.md).

## License

GNU General Public License v3.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
