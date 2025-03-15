import time
import hashlib
import random
import threading
import queue
import reticulum as ret
import logging
import yaml
import os
import asyncio
import argparse

# Configuration (loaded from config.yaml)
config_path = "akita_config.yaml"
if os.path.exists(config_path):
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
else:
    config = {
        "akita_namespace": ret.Identity().hash,
        "akita_port": 48000,
        "update_interval": 60,
        "cache_ttl": 300,
        "log_level": "INFO",
        "max_cache_size": 1000,
        "gossip_interval": 120,
        "ttl_interval": 3600,
        "default_ttl": 86400,
        "gossip_neighbors": 5,
        "rate_limit": 10,
        "namespace_owners": {},
        "reputation": {},
    }
    with open(config_path, "w") as f:
        yaml.dump(config, f)

AKITA_NAMESPACE = config["akita_namespace"]
AKITA_PORT = config["akita_port"]
UPDATE_INTERVAL = config["update_interval"]
CACHE_TTL = config["cache_ttl"]
MAX_CACHE_SIZE = config["max_cache_size"]
GOSSIP_INTERVAL = config["gossip_interval"]
TTL_INTERVAL = config["ttl_interval"]
DEFAULT_TTL = config["default_ttl"]
GOSSIP_NEIGHBORS = config["gossip_neighbors"]
RATE_LIMIT = config["rate_limit"]
NAMESPACE_OWNERS = config["namespace_owners"]
REPUTATION = config["reputation"]

# Logging setup
logging.basicConfig(level=config["log_level"], format="%(asctime)s - %(levelname)s - %(message)s")

# Data Structures
registry = {}
cache = {}
update_queue = queue.Queue()
request_timestamps = []

def generate_signature(data, identity):
    return identity.sign(data)

def verify_signature(data, signature, identity_hash):
    try:
        identity = ret.Identity(identity_hash)
        return identity.verify(data, signature)
    except Exception as e:
        logging.error(f"Signature verification error: {e}")
        return False

def register_name(namespace, name, rid, identity, ttl=DEFAULT_TTL):
    if namespace in NAMESPACE_OWNERS and NAMESPACE_OWNERS[namespace] != identity.hash:
        logging.warning(f"Unauthorized registration in namespace {namespace}")
        return
    data = f"{namespace}:{name}:{rid}:{ttl}".encode("utf-8")
    signature = generate_signature(data, identity)
    registry.setdefault(namespace, {})[name] = (rid, time.time(), signature, time.time() + ttl)
    logging.info(f"Registered {name} in {namespace} to {rid} with TTL {ttl}")

def update_name(namespace, name, rid, identity, ttl=DEFAULT_TTL):
    register_name(namespace, name, rid, identity, ttl)

def resolve_name(namespace, name):
    if namespace in cache and name in cache[namespace] and time.time() - cache[namespace][name][1] < CACHE_TTL:
        return cache[namespace][name][0]

    if namespace in registry and name in registry[namespace]:
        rid, timestamp, signature, expiration = registry[namespace][name]
        if time.time() > expiration:
            del registry[namespace][name]
            return None
        if verify_signature(f"{namespace}:{name}:{rid}:{expiration-time.time()+timestamp}".encode("utf-8"), signature, ret.Identity(rid).hash):
            cache.setdefault(namespace, {})[name] = (rid, time.time())
            if len(cache) > MAX_CACHE_SIZE:
                remove_oldest_cache()
            return rid
        else:
            logging.warning(f"Signature verification failed for {name} in {namespace}")
            return None
    return None

def handle_incoming(interface, packet):
    if not rate_limit_check():
        logging.warning("Rate limit exceeded. Packet dropped.")
        return
    try:
        data = packet["content"].decode("utf-8")
        parts = data.split(":")

        if parts[0] == "REGISTER":
            namespace, name, rid, identity_hash, signature, ttl = parts[1], parts[2], parts[3], parts[4], parts[5], int(parts[6])
            data_to_verify = f"{namespace}:{name}:{rid}:{ttl}".encode("utf-8")
            if verify_signature(data_to_verify, signature, identity_hash):
                register_name(namespace, name, rid, ret.Identity(identity_hash), ttl)
        elif parts[0] == "UPDATE":
            namespace, name, rid, identity_hash, signature, ttl = parts[1], parts[2], parts[3], parts[4], parts[5], int(parts[6])
            data_to_verify = f"{namespace}:{name}:{rid}:{ttl}".encode("utf-8")
            if verify_signature(data_to_verify, signature, identity_hash):
                update_name(namespace, name, rid, ret.Identity(identity_hash), ttl)
        elif parts[0] == "RESOLVE":
            namespace, name, requester_rid = parts[1], parts[2], parts[3]
            rid = resolve_name(namespace, name)
            if rid:
                response = f"RESPONSE:{namespace}:{name}:{rid}".encode("utf-8")
                ret.destination(requester_rid).announce(response)
                update_reputation(packet["from"], 1)
            else:
                update_reputation(packet["from"], -1)
        elif parts[0] == "GOSSIP":
            gossip_data = parts[1]
            try:
                gossip_registry = yaml.safe_load(gossip_data)
                update_registry(gossip_registry)
            except Exception as e:
                logging.error(f"Error processing gossip data: {e}")
        elif parts[0] == "NAMESPACE_CREATE":
            namespace, owner_hash, signature = parts[1], parts[2], parts[3]
            handle_namespace_create(namespace, owner_hash, signature)

    except Exception as e:
        logging.error(f"Error handling packet: {e}")

def periodic_update(identity, namespace, name, rid, ttl=DEFAULT_TTL):
    while True:
        time.sleep(UPDATE_INTERVAL + random.randint(0, UPDATE_INTERVAL // 2))
        update_queue.put((namespace, name, rid, identity, ttl))

def update_worker():
    while True:
        namespace, name, rid, identity, ttl = update_queue.get()
        data = f"UPDATE:{namespace}:{name}:{rid}:{identity.hash}:{ttl}".encode("utf-8")
        signature = generate_signature(f"{namespace}:{name}:{rid}:{ttl}".encode("utf-8"), identity)
        message = f"{data.decode('utf-8')}:{signature.decode('utf-8')}".encode("utf-8")
        ret.destination(AKITA_NAMESPACE).announce(message)
        update_queue.task_done()

def start_akita(identity, name, namespace=AKITA_NAMESPACE, ttl = DEFAULT_TTL):
    ret.interfaces.add_interface(ret.UDPInterface(AKITA_PORT))
    ret.destination(AKITA_NAMESPACE).register_incoming(handle_incoming)
    register_name(namespace, name, identity.hash, identity, ttl)
    threading.Thread(target=periodic_update, args=(identity, namespace, name, identity.hash, ttl), daemon=True).start()
    threading.Thread(target=update_worker, daemon=True).start()
    asyncio.create_task(gossip_worker())
    threading.Thread(target=ttl_worker, daemon=True).start()
    logging.info("Akita started.")

def resolve_akita_name(namespace, name, requester_identity):
    data = f"RESOLVE:{namespace}:{name}:{requester_identity.hash}".encode("utf-8")
    ret.destination(AKITA_NAMESPACE).announce(data.encode("utf-8"))
    start_time = time.time()
    while time.time() - start_time < 5:
        for packet in ret.destination(requester_identity.hash).packets:
            try:
                data = packet["content"].decode("utf-8")
                parts = data.split(":")
                if parts[0] == "RESPONSE" and parts[1] == namespace and parts[2] == name:
                    return parts[3]
            except:
                pass
        time.sleep(0.1)
    return None

async def gossip_worker():
    while True:
        await asyncio.sleep(GOSSIP_INTERVAL + random.randint(0, GOSSIP_INTERVAL // 2))
        gossip_data = yaml.dump(registry).encode("utf-8")
        message = f"GOSSIP:{gossip_data.decode('utf-8')}".encode("utf-8")
        neighbors = list(ret.destination(AKITA_NAMESPACE).neighbors)
        if neighbors:
            target_nodes = random.sample(neighbors, min(GOSSIP_NEIGHBORS, len(neighbors)))
            for node in target_nodes:
                ret.destination(node).announce(message)

def update_registry(gossip_registry):
    for namespace, names in gossip_registry.items():
        for name, (rid, timestamp, signature, expiration) in names.items():
            if namespace not in registry or name not in registry[namespace] or registry[namespace][name][1] < timestamp:
                if verify_signature(f"{namespace}:{name}:{rid}:{expiration-time.time()+timestamp}".encode("utf-8"), signature, ret.Identity(rid).hash):
                    registry.setdefault(namespace, {})[name] = (rid, timestamp, signature, expiration)
                    logging.info(f"Updated {name} in {namespace} via gossip")
                else:
                    logging.warning(f"Gossip signature verification failed for {name} in {namespace}")

def ttl_worker():
    while True:
        time.sleep(TTL_INTERVAL)
        now = time.time()
        for namespace, names in list(registry.items()):
            for name, (rid, timestamp, signature, expiration) in list(names.items()):
                if now > expiration:
                    del registry[namespace][name]
                    logging.info(f"Removed expired registration {name} in {namespace}")
        remove_expired_cache()

def remove_expired_cache():
    now = time.time()
    for namespace, names in list(cache.items()):
        for name, (rid, timestamp) in list(names.items()):
            if now - timestamp > CACHE_TTL:
                del cache[namespace][name]

def remove_oldest_cache():
    oldest_timestamp = float('inf')
    oldest_namespace = None
    oldest_name = None
    for namespace, names in cache.items():
        for name, (rid, timestamp) in names.items():
            if timestamp < oldest_timestamp:
                oldest_timestamp = timestamp
                oldest_namespace = namespace
                oldest_name = name
    if oldest_namespace and oldest_name:
        del cache[oldest_namespace][oldest_name]

def rate_limit_check():
    now = time.time()
    request_timestamps[:] = [ts for ts in request_timestamps if now - ts < 1]
    if len(request_timestamps) >= RATE_LIMIT:
        return False
    request_timestamps.append(now)
    return True

def create_namespace(namespace, owner_identity):
    data = f"NAMESPACE_CREATE:{namespace}:{owner_identity.hash}".encode("utf-8")
    signature = generate_signature(data, owner_identity)
    message = f"{data.decode('utf-8')}:{signature.decode('utf-8')}".encode("utf-8")
    ret.destination(AKITA_NAMESPACE).announce(message)

def handle_namespace_create(namespace, owner_hash, signature):
    data = f"NAMESPACE_CREATE:{namespace}:{owner_hash}".encode("utf-8")
    if verify_signature(data, signature, owner_hash):
        NAMESPACE_OWNERS[namespace] = owner_hash
        config["namespace_owners"] = NAMESPACE_OWNERS
        with open(config_path, "w") as f:
            yaml.dump(config, f)
        logging.info(f"Namespace {namespace} created by {owner_hash}")
    else:
        logging.warning(f"Namespace creation signature verification failed.")

def update_reputation(rid, score_change):
    REPUTATION[rid] = REPUTATION.get(rid, 0) + score_change
    config["reputation"] = REPUTATION
    with open(config_path, "w") as f:
        yaml.dump(config, f)

def cli():
    parser = argparse.ArgumentParser(description="Akita DDNS CLI")
    parser.add_argument("command", choices=["register", "resolve", "create_namespace"], help="Command to execute")
    parser.add_argument("--name", help="Name to register or resolve")
    parser.add_argument("--namespace", default=AKITA_NAMESPACE, help="Namespace")
    parser.add_argument("--rid", help="RID to register")
    parser.add_argument("--owner", help="Owner RID for namespace creation")
    args = parser.parse_args()

    if args.command == "register":
        if args.name and args.rid:
            register_name(args.namespace, args.name, args.rid, ret.Identity())
        else:
            print("Missing name or RID.")
    elif args.command == "resolve":
        if args.name:
            rid = resolve_akita_name(args.namespace, args.name, ret.Identity())
            if rid:
                print(f"Resolved {args.name} to {rid}")
            else:
                print("Resolution failed.")
        else:
            print("Missing name.")
    elif args.command == "create_namespace":
        if args.namespace and args.owner:
            owner_identity = ret.Identity(args.owner)
            create_namespace(args.namespace, owner_identity)
        else:
            print("Missing namespace or owner.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        cli()
    else:
        my_identity = ret.Identity()
        start_akita(my_identity, "my-device.home", AKITA_NAMESPACE)
        try:
            asyncio.run(gossip_worker())
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            print("Akita stopped.")
