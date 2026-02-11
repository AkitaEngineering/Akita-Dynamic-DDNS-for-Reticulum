# akita_ddns/network.py
import asyncio
import logging
import random
import time
import yaml
import RNS as ret

from .config import get_config
from .utils import RateLimiter
from .crypto import generate_signature, verify_signature, verify_signature_with_public_key, identity_from_public_key

log = logging.getLogger(__name__)
APP_NAME = "akita_ddns"

class AkitaServer:
    def __init__(self, r_instance, registry, cache, ns_mgr, rep_mgr, identity):
        self.r = r_instance
        self.reg = registry
        self.cache = cache
        self.ns_mgr = ns_mgr
        self.rep_mgr = rep_mgr
        self.config = get_config()
        
        self.rate_limiter = RateLimiter(self.config.get("rate_limit_requests_per_sec", 10))
        self.identity = identity

        # Listener
        self.listener = ret.Destination(
            None,
            ret.Destination.IN,
            ret.Destination.PLAIN,
            APP_NAME, "broadcast"
        )
        self.listener.set_proof_strategy(ret.Destination.PROVE_NONE)
        self.listener.set_packet_callback(self._on_packet)
        
        # Sender
        self.sender = ret.Destination(
            None,
            ret.Destination.OUT,
            ret.Destination.PLAIN,
            APP_NAME, "broadcast"
        )
        self._shutdown = False

    def _on_packet(self, data, packet):
        if self._shutdown or not self.rate_limiter.check(): return
        if not packet or not packet.source_hash: return
        if packet.source_hash == self.identity.hash: return

        try:
            text = data.decode("utf-8")
            cmd, payload = text.split(":", 1)
            
            if cmd == "REGISTER": self._handle_register(payload, packet.source_hash)
            elif cmd == "RESOLVE": self._handle_resolve(payload, packet.source_hash)
            elif cmd == "GOSSIP": self._handle_gossip(payload, packet.source_hash)
            elif cmd == "NAMESPACE_CREATE": self._handle_ns_create(payload, packet.source_hash)
            else: self.rep_mgr.update_reputation(packet.source_hash, -1)
            
        except Exception as e:
            log.error(f"Packet error: {e}")

    def _handle_register(self, payload, src):
        # ns:name:rid:id_hash:pubkey:sig:ttl
        try:
            parts = payload.split(":")
            if len(parts) != 7: raise ValueError
            ns, name, rid_hex, id_hex, pub_hex, sig_hex, ttl = parts
            
            rid = bytes.fromhex(rid_hex)
            signer = bytes.fromhex(id_hex)
            pubkey = bytes.fromhex(pub_hex)
            sig = bytes.fromhex(sig_hex)
            
            if signer != src: return # Mismatch
            identity = identity_from_public_key(pubkey)
            if not identity or identity.hash != signer: return
            
            # Verify Sig
            verify_data = f"{ns}:{name}:{rid_hex}:{ttl}".encode("utf-8")
            if not verify_signature_with_public_key(verify_data, sig, pubkey): return
            
            # Check Auth
            if not self.ns_mgr.is_authorized(ns, signer): return
            
            # Register
            self.reg.register(ns, name, rid, time.time(), sig, time.time() + int(ttl), pubkey)
            self.rep_mgr.update_reputation(src, 1)
            
        except Exception as e:
            log.error(f"Error handling register: {e}")

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
                resp_data = f"RESPONSE:{ns}:{name}:{rid.hex()}:{src.hex()}".encode("utf-8")
                dest = ret.Destination(
                    None,
                    ret.Destination.OUT,
                    ret.Destination.PLAIN,
                    APP_NAME, "response"
                )
                dest.set_proof_strategy(ret.Destination.PROVE_NONE)
                ret.Packet(dest, resp_data).send()
                
        except Exception as e:
            log.error(f"Error handling resolve: {e}")

    def _handle_gossip(self, payload, src):
        try:
            data = yaml.safe_load(payload)
            # Deserialize
            processed = {}
            for ns, names in data.items():
                processed[ns] = {}
                for n, e in names.items():
                    # hex -> bytes
                    processed[ns][n] = (bytes.fromhex(e[0]), e[1], bytes.fromhex(e[2]), e[3], bytes.fromhex(e[4]))
            
            owners = self.ns_mgr.get_owners()
            self.reg.process_gossip(processed, owners, src)
            self.rep_mgr.update_reputation(src, 1)
        except Exception as e:
            log.error(f"Error handling gossip: {e}")

    def _handle_ns_create(self, payload, src):
        try:
            ns, owner_hex, pub_hex, sig_hex = payload.split(":")
            if bytes.fromhex(owner_hex) != src: return
            if self.ns_mgr.create_namespace(ns, bytes.fromhex(owner_hex), bytes.fromhex(pub_hex), bytes.fromhex(sig_hex)):
                self.rep_mgr.update_reputation(src, 1)
        except Exception as e:
            log.error(f"Error handling namespace create: {e}")

    async def run_gossip_loop(self):
        while not self._shutdown:
            await asyncio.sleep(self.config["gossip_interval"] * random.uniform(0.9, 1.1))
            try:
                data = self.reg.get_registry_for_gossip()
                if not data: continue
                
                # Serialize
                s_data = {}
                for ns, names in data.items():
                    s_data[ns] = {n: (e[0].hex(), e[1], e[2].hex(), e[3], e[4].hex()) for n, e in names.items()}
                
                payload = yaml.dump(s_data).encode("utf-8")
                ret.Packet(self.sender, b"GOSSIP:" + payload).send()
            except Exception as e:
                log.error(f"Error in gossip loop: {e}")

    async def run_periodic_tasks(self):
        while not self._shutdown:
            await asyncio.sleep(self.config["ttl_check_interval"])
            self.reg.run_ttl_check()
            self.cache.run_ttl_check()

    def shutdown(self):
        self._shutdown = True
        self.listener.set_packet_callback(None)

    # CLI Helpers
    def send_register(self, name, ns, rid, identity, ttl):
        data = f"{ns}:{name}:{rid.hex()}:{ttl}".encode("utf-8")
        sig = generate_signature(data, identity)
        pubkey_hex = identity.get_public_key().hex()
        msg = f"REGISTER:{ns}:{name}:{rid.hex()}:{identity.hash.hex()}:{pubkey_hex}:{sig.hex()}:{ttl}".encode("utf-8")
        return ret.Packet(self.sender, msg).send()

    def send_resolve(self, name, ns, identity):
        msg = f"RESOLVE:{ns}:{name}:{identity.hash.hex()}".encode("utf-8")
        return ret.Packet(self.sender, msg).send()

    def send_ns_create(self, ns, identity):
        data = f"NAMESPACE_CREATE:{ns}:{identity.hash.hex()}".encode("utf-8")
        sig = generate_signature(data, identity)
        pubkey_hex = identity.get_public_key().hex()
        msg = f"{data.decode()}:{pubkey_hex}:{sig.hex()}".encode("utf-8")
        return ret.Packet(self.sender, msg).send()
