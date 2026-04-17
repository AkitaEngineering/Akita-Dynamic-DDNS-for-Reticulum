import types

from akita_ddns.network import AkitaServer


class AllowAllRateLimiter:
    def check(self):
        return True


def test_on_packet_does_not_require_source_hash():
    server = AkitaServer.__new__(AkitaServer)
    server._shutdown = False
    server.rate_limiter = AllowAllRateLimiter()

    seen = []
    server._handle_register = lambda payload: seen.append(("REGISTER", payload))
    server._handle_resolve = lambda payload: seen.append(("RESOLVE", payload))
    server._handle_gossip = lambda payload: seen.append(("GOSSIP", payload))
    server._handle_ns_create = lambda payload: seen.append(("NAMESPACE_CREATE", payload))

    server._on_packet(b"REGISTER:testns:testname:rid:identity:pubkey:sig:60", types.SimpleNamespace())

    assert seen == [("REGISTER", "testns:testname:rid:identity:pubkey:sig:60")]