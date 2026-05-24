import asyncio
import logging
import os
import time
from aiohttp import web

from .storage import PersistentStorage, Registry
from .namespace import NamespaceManager
from .reputation import ReputationManager
from .network import AkitaServer

log = logging.getLogger(__name__)

class WebUI:
    def __init__(self, config, server: AkitaServer, reg: Registry, ns_mgr: NamespaceManager, rep_mgr: ReputationManager):
        self.config = config
        self.server = server
        self.reg = reg
        self.ns_mgr = ns_mgr
        self.rep_mgr = rep_mgr
        self.app = web.Application()
        self.runner = None
        self.site = None

        # Setup Routes
        self.app.router.add_get('/api/registry', self.api_registry)
        self.app.router.add_get('/api/namespaces', self.api_namespaces)
        self.app.router.add_get('/api/reputation', self.api_reputation)
        self.app.router.add_post('/api/register', self.api_register)
        self.app.router.add_post('/api/resolve', self.api_resolve)
        
        # Static files
        static_dir = os.path.join(os.path.dirname(__file__), 'static')
        os.makedirs(static_dir, exist_ok=True)
        # Default route to index.html
        self.app.router.add_get('/', self.index_handler)
        self.app.router.add_static('/', static_dir, show_index=True)

    async def index_handler(self, request):
        return web.FileResponse(os.path.join(os.path.dirname(__file__), 'static', 'index.html'))

    async def api_registry(self, request):
        now = time.time()
        res = []
        with self.reg._lock:
            for ns, names in self.reg._registry.items():
                for name, entry in names.items():
                    if now < entry[3]:
                        res.append({
                            "namespace": ns,
                            "name": name,
                            "rid": entry[0].hex(),
                            "timestamp": entry[1],
                            "expiration": entry[3],
                            "pubkey": entry[4].hex()
                        })
        return web.json_response(res)

    async def api_namespaces(self, request):
        return web.json_response(self.ns_mgr.get_owners())

    async def api_reputation(self, request):
        with self.rep_mgr._lock:
            return web.json_response(self.rep_mgr._rep.copy())

    async def api_register(self, request):
        try:
            data = await request.json()
            name = data.get("name")
            ns = data.get("namespace", self.config["akita_namespace_identity_hash"])
            rid_hex = data.get("rid")
            ttl = int(data.get("ttl", self.config["default_ttl"]))
            if not name or not rid_hex:
                return web.json_response({"error": "Missing name or rid"}, status=400)
            
            rid = bytes.fromhex(rid_hex)
            if self.server.send_register(name, ns, rid, self.server.identity, ttl):
                return web.json_response({"status": "sent"})
            return web.json_response({"error": "Failed to send"}, status=500)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def api_resolve(self, request):
        try:
            data = await request.json()
            name = data.get("name")
            ns = data.get("namespace", self.config["akita_namespace_identity_hash"])
            if not name:
                return web.json_response({"error": "Missing name"}, status=400)
            
            if self.server.send_resolve(name, ns, self.server.identity):
                return web.json_response({"status": "sent"})
            return web.json_response({"error": "Failed to send"}, status=500)
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        host = self.config.get("web_ui_host", "127.0.0.1")
        port = self.config.get("web_ui_port", 48080)
        self.site = web.TCPSite(self.runner, host, port)
        await self.site.start()
        log.info(f"Web UI Dashboard started at http://{host}:{port}")

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
