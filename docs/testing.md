# Testing Akita DDNS

Testing a decentralized, peer-to-peer system like Akita DDNS is different from testing a typical client-server application. Some logic can be covered well with unit tests, but live Reticulum behavior still needs manual or future integration coverage.

## Current Status

- Unit tests cover core helper and protocol-validation paths.
- Manual multi-node testing is still required for real Reticulum network behavior.
- Integration and end-to-end tests are not implemented yet.

## What Is Covered Today

The current automated suite exercises these areas:

- `config.load_config` path-sensitive reload behavior
- `crypto.identity_from_public_key`
- `crypto.verify_signature_with_public_key`
- `network.AkitaServer._on_packet` dispatch behavior
- `storage.Registry.process_gossip`
- `utils.parse_name`
- `utils.RateLimiter`

Current test files:

- `tests/test_config.py`
- `tests/test_crypto.py`
- `tests/test_network.py`
- `tests/test_storage.py`
- `tests/test_utils.py`

## Running Unit Tests

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the suite:

```bash
pytest tests/
```

## Manual Multi-Node Testing

Manual testing is the current way to validate peer-to-peer behavior across real Reticulum nodes.

### Setup

Use separate terminals and separate config files. Nodes that should participate in the same Akita network must share the same `akita_namespace_identity_hash`, but should use different persistence directories.

```bash
# Terminal 1 (Node A)
cp akita_config.yaml node_a_config.yaml
# Edit node_a_config.yaml: persistence_path: ./akita_state_a
python -m akita_ddns.main --config node_a_config.yaml server

# Terminal 2 (Node B)
cp akita_config.yaml node_b_config.yaml
# Edit node_b_config.yaml: persistence_path: ./akita_state_b
python -m akita_ddns.main --config node_b_config.yaml server

# Terminal 3 (CLI interaction)
# Use any matching config file for client operations
```

### Suggested Scenarios

1. Registration: Register names on Node A, wait for gossip, and verify that Node B can resolve them.
2. Resolution: Resolve names registered only on Node B from Node A.
3. Updates: Change an existing registration on one node and verify that the newer value propagates.
4. TTL expiry: Register a short-lived name and confirm it disappears after expiry with `cli list --registry`.
5. Namespace ownership: Create a namespace on one node, verify another identity cannot publish into it, then verify the owner identity can.
6. Persistence: Restart nodes and confirm non-expired state is still available through `cli list` or `cli resolve`.
7. Rate limiting: Send repeated rapid requests and inspect logs for throttling behavior.
8. Gossip consistency: Compare `cli list --registry` output across peers after gossip intervals.
9. Local state inspection: Check `cli list --registry`, `cli list --namespaces`, and `cli list --reputation` during tests.

## Integration Testing Goals

Integration tests should eventually validate interactions between modules and the network layer without depending on a full external deployment.

Useful targets include:

- Register and resolve flows through mocked Reticulum destinations and packets
- Gossip message exchange and merge behavior
- Namespace creation and ownership enforcement
- Cache and TTL behavior across module boundaries

Recommended future location:

- `tests/integration/`

## End-to-End Testing Goals

End-to-end tests should exercise full application behavior in a controlled multi-node environment.

Useful approaches include:

- Containerized multi-node setups
- Scripted CLI interactions
- Assertions on visible outputs and persisted state

Expected challenges:

- More complex environment setup
- Longer execution time
- Managing network timing and discovery behavior

## Conclusion

The current test suite is enough to validate the core non-network logic and several protocol assumptions that are easy to break. It is not enough to prove full live-network correctness across multiple Reticulum peers. Manual testing is still the right validation path for that until integration or end-to-end coverage is added.
