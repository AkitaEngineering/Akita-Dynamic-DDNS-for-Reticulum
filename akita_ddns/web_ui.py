"""Read-only-by-default HTTP dashboard."""

import hmac
import logging
import os
from typing import Any, Dict, Optional

from aiohttp import web

from .namespace import NamespaceManager
from .network import AkitaServer
from .reputation import ReputationManager
from .storage import Registry
from .utils import validate_hash, validate_label

log = logging.getLogger(__name__)


@web.middleware
async def security_headers(request, handler):
    response = await handler(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'"
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


class WebUI:
    def __init__(
        self,
        config: Dict[str, Any],
        server: AkitaServer,
        reg: Registry,
        ns_mgr: NamespaceManager,
        rep_mgr: ReputationManager,
    ):
        self.config = config
        self.server = server
        self.reg = reg
        self.ns_mgr = ns_mgr
        self.rep_mgr = rep_mgr
        self.static_dir = os.path.join(os.path.dirname(__file__), "static")
        self.app = web.Application(
            client_max_size=config["web_ui_max_request_bytes"],
            middlewares=[security_headers],
        )
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.BaseSite] = None

        self.app.router.add_get("/healthz", self.health)
        self.app.router.add_get("/api/registry", self.api_registry)
        self.app.router.add_get("/api/namespaces", self.api_namespaces)
        self.app.router.add_get("/api/reputation", self.api_reputation)
        self.app.router.add_post("/api/resolve", self.api_resolve)
        if config["web_ui_allow_mutations"]:
            self.app.router.add_post("/api/register", self.api_register)
        self.app.router.add_get("/", self.index_handler)
        self.app.router.add_static("/static", self.static_dir, show_index=False)

    def _authorized(self, request: web.Request) -> bool:
        expected = self.config.get("web_ui_api_token")
        if not expected:
            return False
        supplied = request.headers.get("Authorization", "")
        prefix = "Bearer "
        return supplied.startswith(prefix) and hmac.compare_digest(
            supplied[len(prefix) :], expected
        )

    async def index_handler(self, request):
        return web.FileResponse(os.path.join(self.static_dir, "index.html"))

    async def health(self, request):
        return web.json_response({"status": "ok"})

    async def api_registry(self, request):
        return web.json_response(self.reg.snapshot())

    async def api_namespaces(self, request):
        return web.json_response(self.ns_mgr.get_owners())

    async def api_reputation(self, request):
        return web.json_response(self.rep_mgr.snapshot())

    async def api_register(self, request):
        if not self._authorized(request):
            raise web.HTTPUnauthorized(headers={"WWW-Authenticate": "Bearer"})
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            raw_name = data.get("name")
            if not isinstance(raw_name, str):
                raise ValueError("name is required")
            name = validate_label(raw_name, "name")
            namespace = validate_label(
                data.get("namespace", self.config["akita_namespace_identity_hash"]),
                "namespace",
            )
            rid = bytes.fromhex(data.get("rid", ""))
            validate_hash(rid, "RID")
            ttl = int(data.get("ttl", self.config["default_ttl"]))
            if not self.server.register_local(name, namespace, rid, ttl):
                return web.json_response(
                    {"error": "registration was rejected"}, status=409
                )
            return web.json_response({"status": "registered"})
        except (TypeError, ValueError):
            return web.json_response(
                {"error": "invalid registration request"}, status=400
            )

    async def api_resolve(self, request):
        try:
            data = await request.json()
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            raw_name = data.get("name")
            if not isinstance(raw_name, str):
                raise ValueError("name is required")
            name = validate_label(raw_name, "name")
            namespace = validate_label(
                data.get("namespace", self.config["akita_namespace_identity_hash"]),
                "namespace",
            )
            entry = self.reg.resolve(namespace, name)
            if not entry:
                return web.json_response({"error": "not found"}, status=404)
            return web.json_response(
                {
                    "namespace": namespace,
                    "name": name,
                    "rid": entry[0].hex(),
                    "timestamp": entry[1],
                    "expiration": entry[3],
                }
            )
        except (TypeError, ValueError):
            return web.json_response(
                {"error": "invalid resolution request"}, status=400
            )

    async def start(self) -> None:
        index_path = os.path.join(self.static_dir, "index.html")
        if not os.path.isfile(index_path):
            raise RuntimeError(f"Dashboard asset is missing: {index_path}")
        runner = web.AppRunner(self.app, access_log=log)
        await runner.setup()
        self.runner = runner
        host = self.config["web_ui_host"]
        port = self.config["web_ui_port"]
        site = web.TCPSite(runner, host, port)
        await site.start()
        self.site = site
        log.info("Web dashboard started at http://%s:%s", host, port)

    async def stop(self) -> None:
        if self.runner:
            await self.runner.cleanup()
            self.runner = None
            self.site = None
