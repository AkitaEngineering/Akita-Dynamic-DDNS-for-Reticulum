# akita_ddns/network.py
import asyncio
import logging
import random
import time
import yaml
import reticulum as ret

from .config import get_config
from .utils import RateLimiter
from .crypto import generate_signature, verify_signature

log = logging.getLogger(__name__)
APP_NAME = "akita_ddns"

class AkitaServer:
    def __init__(self, r_instance, registry, cache, ns_mgr, rep_mgr):
        self.r = r_instance
        self.reg = registry
        self.cache = cache
        self.ns_mgr = ns_mgr
        self.rep_mgr = rep_mgr
        self.config = get_config()
        
        self.rate_limiter = RateLimiter(self.config.get("rate_limit_requests_per_sec", 10))
        self.identity = self.r.get_identity()
        self.ns_hash = bytes.fromhex(self.config["akita_namespace_identity_hash"])

        # Listener
        self.listener = ret.Destination(
            ret.Identity(identity_hash=self.ns_hash),
            ret.Destination.IN,
            ret.Destination.BROADCAST,
            APP_NAME, "broadcast"
        )
        self.listener.set_proof_strategy(ret.Destination.PROVE_NONE)
        self.listener.register_incoming_callback(self._on_packet)
        
        # Sender
        self.sender = ret.Destination(
            ret.Identity(identity_hash=self.ns_hash),
            ret.Destination.OUT,
            ret.Destination.BROADCAST,
            APP_NAME, "broadcast"
        )
        self._shutdown = False

    def _on_packet(self, hash, interface):
        if self._shutdown or not self.rate_limiter.check(): return
        
        pkt = interface.packet
        if not pkt or not pkt.source_hash: return
        if pkt.source_hash == self.identity.hash: return

        try:
            data = pkt.plaintext.decode("utf-8")
            cmd, payload = data.split(":", 1)
            
            if cmd == "REGISTER": self._handle_register(payload, pkt.source_hash)
            elif cmd == "RESOLVE": self._handle_resolve(payload, pkt.source_hash)
            elif cmd == "GOSSIP": self._handle_gossip(payload, pkt.source_hash)
            elif cmd == "NAMESPACE_CREATE": self._handle_ns_create(payload, pkt.source_hash)
            else: self.rep_mgr.update_reputation(pkt.source_hash, -1)
            
        except Exception as e:
            log.error(f"Packet error: {e}")

    def _handle_register(self, payload, src):
        # ns:name:rid:id_hash:sig:ttl
        try:
            parts = payload.split(":")
            if len(parts) != 6: raise ValueError
            ns, name, rid_hex, id_hex, sig_hex, ttl = parts
            
            rid = bytes.fromhex(rid_hex)
            signer = bytes.fromhex(id_hex)
            sig = bytes.fromhex(sig_hex)
            
            if signer != src: return # Mismatch
            
            # Verify Sig
            verify_data = f"{ns}:{name}:{rid_hex}:{ttl}".encode("utf-8")
            if not verify_signature(verify_data, sig, signer): return
            
            # Check Auth
            if not self.ns_mgr.is_authorized(ns, rid): return
            
            # Register
            self.reg.register(ns, name, rid, time.time(), sig, time.time() + int(ttl))
            self.rep_mgr.update_reputation(src, 1)
            
        except Exception: pass

    def _handle_resolve(self, payload, src):
        # ns:name:req_rid
        try:
            ns, name, req_rid = payload.split(":")
            if bytes.fromhex(req_rid) != src: return
            
            # Check Cache/Registry
            rid = self.cache.get(ns, name)
            if not rid:
                entry = self.reg.resolve(ns, name)
                if entry:
                    rid = entry[0]
                    self.cache.put(ns, name, rid)
            
            if rid:
                # Send Response
                resp_data = f"RESPONSE:{ns}:{name}:{rid.hex()}".encode("utf-8")
                dest = ret.Destination(
                    ret.Identity(identity_hash=src),
                    ret.Destination.OUT,
                    ret.Destination.SINGLE,
                    APP_NAME, "response"
                )
                dest.set_proof_strategy(ret.Destination.PROVE_NONE)
                ret.Packet(dest, resp_data).send()
                
        except Exception as e: log.error(f"Resolve error: {e}")

    def _handle_gossip(self, payload, src):
        try:
            data = yaml.safe_load(payload)
            # Deserialize
            processed = {}
            for ns, names in data.items():
                processed[ns] = {}
                for n, e in names.items():
                    # hex -> bytes
                    processed[ns][n] = (bytes.fromhex(e[0]), e[1], bytes.fromhex(e[2]), e[3])
            
            owners = self.ns_mgr.get_owners()
            self.reg.process_gossip(processed, owners, src)
            self.rep_mgr.update_reputation(src, 1)
        except Exception: pass

    def _handle_ns_create(self, payload, src):
        try:
            ns, owner_hex, sig_hex = payload.split(":")
            if bytes.fromhex(owner_hex) != src: return
            if self.ns_mgr.create_namespace(ns, bytes.fromhex(owner_hex), bytes.fromhex(sig_hex)):
                self.rep_mgr.update_reputation(src, 1)
        except Exception: pass

    async def run_gossip_loop(self):
        while not self._shutdown:
            await asyncio.sleep(self.config["gossip_interval"] * random.uniform(0.9, 1.1))
            try:
                data = self.reg.get_registry_for_gossip()
                if not data: continue
                
                # Serialize
                s_data = {}
                for ns, names in data.items():
                    s_data[ns] = {n: (e[0].hex(), e[1], e[2].hex(), e[3]) for n, e in names.items()}
                
                payload = yaml.dump(s_data).encode("utf-8")
                ret.Packet(self.sender, b"GOSSIP:" + payload).send()
            except Exception as e: log.error(f"Gossip error: {e}")

    async def run_periodic_tasks(self):
        while not self._shutdown:
            await asyncio.sleep(self.config["ttl_check_interval"])
            self.reg.run_ttl_check()
            self.cache.run_ttl_check()

    def shutdown(self):
        self._shutdown = True
        self.listener.unregister_incoming_callback()

    # CLI Helpers
    def send_register(self, name, ns, rid, identity, ttl):
        data = f"{ns}:{name}:{rid.hex()}:{ttl}".encode("utf-8")
        sig = generate_signature(data, identity)
        msg = f"REGISTER:{ns}:{name}:{rid.hex()}:{identity.hash.hex()}:{sig.hex()}:{ttl}".encode("utf-8")
        return ret.Packet(self.sender, msg).send()

    def send_resolve(self, name, ns, identity):
        msg = f"RESOLVE:{ns}:{name}:{identity.hash.hex()}".encode("utf-8")
        return ret.Packet(self.sender, msg).send()

    def send_ns_create(self, ns, identity):
        data = f"NAMESPACE_CREATE:{ns}:{identity.hash.hex()}".encode("utf-8")
        sig = generate_signature(data, identity)
        msg = f"{data.decode()}:{sig.hex()}".encode("utf-8")
        return ret.Packet(self.sender, msg).send()
