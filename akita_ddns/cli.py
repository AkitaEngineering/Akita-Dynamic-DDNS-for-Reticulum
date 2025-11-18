# akita_ddns/cli.py
import argparse
import time
import threading
import sys
import reticulum as ret
import logging

from .config import get_config
from .utils import parse_name
from .network import APP_NAME
from .crypto import generate_signature

log = logging.getLogger(__name__)

_res_event = threading.Event()
_res_data = None

def _on_response(pk, iface):
    global _res_data
    try:
        data = iface.packet.plaintext.decode().split(":")
        if data[0] == "RESPONSE":
            _res_data = data[3] # rid_hex
            _res_event.set()
    except: pass

def run_cli(args, config, r_instance):
    # --- Identity Setup ---
    identity = None
    # Determine if we need an identity file or can use default
    if hasattr(args, 'identity') and args.identity:
        identity = ret.Identity.from_file(args.identity)
        if not identity:
            print("Error loading identity file.")
            sys.exit(1)
    elif hasattr(args, 'owner_identity') and args.owner_identity:
        identity = ret.Identity.from_file(args.owner_identity)
        if not identity:
            print("Error loading owner identity file.")
            sys.exit(1)
    else:
        # Use default if available, else create ephemeral
        identity = r_instance.get_identity()
        if not identity:
             identity = ret.Identity()
             # Don't save ephemeral

    # CRITICAL FIX: Set the active identity for this Reticulum instance
    # so outgoing packets use the correct source hash.
    r_instance.set_identity(identity)

    # --- Network Setup ---
    ns_hash = bytes.fromhex(config["akita_namespace_identity_hash"])
    sender = ret.Destination(
        ret.Identity(identity_hash=ns_hash),
        ret.Destination.OUT,
        ret.Destination.BROADCAST,
        APP_NAME, "broadcast"
    )

    # Listener for Resolve
    if args.command == "resolve":
        listener = ret.Destination(
            identity,
            ret.Destination.IN,
            ret.Destination.SINGLE,
            APP_NAME, "response"
        )
        listener.set_proof_strategy(ret.Destination.PROVE_NONE)
        listener.register_incoming_callback(_on_response)

    # --- Commands ---
    if args.command == "register":
        name, ns = parse_name(args.name, config["akita_namespace_identity_hash"])
        rid_bytes = bytes.fromhex(args.rid) if args.rid else identity.hash
        ttl = args.ttl or config["default_ttl"]
        
        # Sign
        data = f"{ns}:{name}:{rid_bytes.hex()}:{ttl}".encode("utf-8")
        sig = generate_signature(data, identity)
        
        msg = f"REGISTER:{ns}:{name}:{rid_bytes.hex()}:{identity.hash.hex()}:{sig.hex()}:{ttl}".encode("utf-8")
        if ret.Packet(sender, msg).send():
            print(f"Registration sent for {name}@{ns}")
        else:
            print("Failed to send registration.")

    elif args.command == "resolve":
        name, ns = parse_name(args.name, config["akita_namespace_identity_hash"])
        msg = f"RESOLVE:{ns}:{name}:{identity.hash.hex()}".encode("utf-8")
        
        if ret.Packet(sender, msg).send():
            print(f"Resolving {name}@{ns}...")
            if _res_event.wait(args.timeout):
                print(f"Resolved: {_res_data}")
            else:
                print("Resolution timed out.")
        else:
            print("Failed to send resolve request.")

    elif args.command == "create_namespace":
        ns = args.namespace
        data = f"NAMESPACE_CREATE:{ns}:{identity.hash.hex()}".encode("utf-8")
        sig = generate_signature(data, identity)
        msg = f"{data.decode()}:{sig.hex()}".encode("utf-8")
        
        if ret.Packet(sender, msg).send():
             print(f"Namespace creation sent for {ns}")
        else:
             print("Failed to send.")

    elif args.command == "list":
        # Import storage only here
        from .storage import PersistentStorage
        s = PersistentStorage(config)
        if args.registry:
             print("Registry:", s.load_registry())
        if args.namespaces:
             print("Namespaces:", s.load_namespaces())
        if args.reputation:
             print("Reputation:", s.load_reputation())


def setup_cli_parser():
    p = argparse.ArgumentParser(description="Akita CLI")
    sp = p.add_subparsers(dest="command", required=True)
    
    reg = sp.add_parser("register")
    reg.add_argument("--name", required=True)
    reg.add_argument("--rid")
    reg.add_argument("--ttl", type=int)
    reg.add_argument("--identity")
    
    res = sp.add_parser("resolve")
    res.add_argument("--name", required=True)
    res.add_argument("--timeout", type=float, default=5.0)
    res.add_argument("--identity")
    
    ns = sp.add_parser("create_namespace")
    ns.add_argument("--namespace", required=True)
    ns.add_argument("--owner_identity")
    
    lst = sp.add_parser("list")
    lst.add_argument("--registry", action="store_true")
    lst.add_argument("--namespaces", action="store_true")
    lst.add_argument("--reputation", action="store_true")
    
    return p
