# akita_ddns/main.py
import sys
import argparse
import asyncio
import logging
import signal
import os

# Try importing Reticulum
try:
    import RNS as ret
except ImportError:
    print("Reticulum not found. Install it via pip.")
    sys.exit(1)

# Local Imports
from .config import load_config, get_config
from .storage import PersistentStorage, Registry, Cache
from .namespace import NamespaceManager
from .utils import load_or_create_identity
from .reputation import ReputationManager
from .network import AkitaServer
from .cli import setup_cli_parser, run_cli

# Logging
logging.basicConfig(level="INFO", format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("akita_ddns")

stop_event = asyncio.Event()
server_ref = None

def sig_handler(sig, frame):
    log.info("Stopping...")
    stop_event.set()
    if server_ref: server_ref.shutdown()

async def main_server_loop():
    global server_ref
    config = get_config()
    
    # Init Reticulum
    r = ret.Reticulum(configdir=config["storage_path"])
    
    # Identity
    identity_path = os.path.join(config["storage_path"], "akita_identity")
    i = load_or_create_identity(identity_path)
    log.info(f"Using identity: {i.hash.hex()}")

    # Components
    storage = PersistentStorage(config)
    reg = Registry(storage, config)
    cache = Cache(config)
    ns = NamespaceManager(storage, config)
    rep = ReputationManager(storage, config)
    
    server = AkitaServer(r, reg, cache, ns, rep, i)
    server_ref = server
    
    # Tasks
    t1 = asyncio.create_task(server.run_gossip_loop())
    t2 = asyncio.create_task(server.run_periodic_tasks())
    
    log.info("Server Running. Ctrl+C to exit.")
    
    # Wait for exit signal
    await stop_event.wait()
    
    # Cleanup
    t1.cancel()
    t2.cancel()
    try: await t1; 
    except asyncio.CancelledError: pass
    try: await t2; 
    except asyncio.CancelledError: pass
    

def main():
    # Load config first
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", help="Path to config file", default="akita_config.yaml")
    parser.add_argument("mode", choices=["server", "cli"], nargs="?", default="server")
    
    # Parse mode first
    args, rem = parser.parse_known_args()
    
    try: load_config(args.config)
    except Exception as e:
        print(f"Config Error: {e}")
        sys.exit(1)
    
    if args.mode == "server":
        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        asyncio.run(main_server_loop())
    else:
        # CLI Mode
        sys.argv = [sys.argv[0]] + rem
        cp = setup_cli_parser()
        c_args = cp.parse_args()
        
        # Reticulum for CLI (minimal logging)
        logging.getLogger().setLevel(logging.CRITICAL)
        r = ret.Reticulum(configdir=get_config()["storage_path"])
        
        run_cli(c_args, get_config(), r)

if __name__ == "__main__":
    main()
