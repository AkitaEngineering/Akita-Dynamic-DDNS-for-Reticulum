import unittest

from aiohttp.test_utils import TestClient, TestServer

from akita_ddns.web_ui import WebUI


class FakeRegistry:
    def snapshot(self):
        return []

    def resolve(self, namespace, name):
        return None


class FakeNamespaces:
    def get_owners(self):
        return {}


class FakeReputation:
    def snapshot(self):
        return {}


class FakeServer:
    def __init__(self):
        self.calls = []

    def register_local(self, name, namespace, rid, ttl):
        self.calls.append((name, namespace, rid, ttl))
        return True


def web_config(mutations=False):
    return {
        "web_ui_max_request_bytes": 4096,
        "web_ui_allow_mutations": mutations,
        "web_ui_api_token": "a" * 32 if mutations else None,
        "akita_namespace_identity_hash": "0" * 32,
        "default_ttl": 300,
        "max_namespaces": 100,
        "max_clock_skew": 300,
    }


class TestWebUI(unittest.IsolatedAsyncioTestCase):
    async def make_client(self, mutations=False):
        server = FakeServer()
        ui = WebUI(
            web_config(mutations),
            server,
            FakeRegistry(),
            FakeNamespaces(),
            FakeReputation(),
        )
        client = TestClient(TestServer(ui.app))
        await client.start_server()
        self.addAsyncCleanup(client.close)
        return client, server

    async def test_health_has_security_headers(self):
        client, _ = await self.make_client()

        response = await client.get("/healthz")

        self.assertEqual(response.status, 200)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    async def test_mutation_route_is_absent_by_default(self):
        client, _ = await self.make_client()

        response = await client.post("/api/register", json={})

        self.assertEqual(response.status, 404)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(
            response.headers["Cross-Origin-Resource-Policy"], "same-origin"
        )

    async def test_mutation_requires_bearer_token(self):
        client, server = await self.make_client(mutations=True)
        body = {"name": "router", "rid": "1" * 32, "ttl": 60}

        unauthorized = await client.post("/api/register", json=body)
        authorized = await client.post(
            "/api/register",
            json=body,
            headers={"Authorization": f"Bearer {'a' * 32}"},
        )

        self.assertEqual(unauthorized.status, 401)
        self.assertEqual(authorized.status, 200)
        self.assertEqual(server.calls[0][0:2], ("router", "0" * 32))
