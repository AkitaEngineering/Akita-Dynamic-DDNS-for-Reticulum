"""Application entry point."""

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import Optional

try:
    import RNS as ret
except ImportError:
    print("Reticulum not found. Install the project dependencies.", file=sys.stderr)
    raise SystemExit(1)

from .cli import run_cli, setup_cli_parser
from .config import ensure_network_id, load_config
from .namespace import NamespaceManager
from .network import AkitaServer
from .reputation import ReputationManager
from .storage import Cache, PersistentStorage, Registry
from .utils import load_or_create_identity

log = logging.getLogger("akita_ddns")
stop_event: Optional[asyncio.Event] = None
server_ref: Optional[AkitaServer] = None


def sig_handler(sig, frame) -> None:
    log.info("Stopping...")
    if server_ref:
        server_ref.shutdown()
    if stop_event:
        stop_event.set()


async def main_server_loop(config) -> None:
    global server_ref, stop_event
    stop_event = asyncio.Event()
    reticulum = ret.Reticulum(configdir=config["storage_path"])
    identity_path = os.path.join(config["storage_path"], "akita_identity")
    identity = load_or_create_identity(identity_path)
    ensure_network_id(config, identity)
    log.info(
        "Using node identity %s on network %s",
        identity.hash.hex(),
        config["akita_namespace_identity_hash"],
    )
    if stop_event.is_set():
        return

    storage = PersistentStorage(config)
    registry = Registry(storage, config)
    cache = Cache(config)
    namespace_manager = NamespaceManager(storage, config)
    reputation_manager = ReputationManager(storage, config)
    registry.reconcile_namespace_owners(
        namespace_manager.get_owners(), config["allow_unowned_namespaces"]
    )
    server = AkitaServer(
        reticulum,
        registry,
        cache,
        namespace_manager,
        reputation_manager,
        identity,
    )
    server_ref = server
    web_ui = None
    tasks = []
    try:
        if config["web_ui_enabled"]:
            from .web_ui import WebUI

            web_ui = WebUI(
                config, server, registry, namespace_manager, reputation_manager
            )
            await web_ui.start()
        tasks = [
            asyncio.create_task(server.run_gossip_loop(), name="akita-gossip"),
            asyncio.create_task(server.run_periodic_tasks(), name="akita-maintenance"),
        ]
        log.info("Server running. Press Ctrl+C to exit.")
        await stop_event.wait()
    finally:
        server.shutdown()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if web_ui:
            await web_ui.stop()
        server_ref = None


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", default="akita_config.yaml")
    parser.add_argument("mode", choices=["server", "cli"], nargs="?", default="server")
    args, remaining = parser.parse_known_args()

    if args.mode == "server" and remaining in (["-h"], ["--help"]):
        print("usage: akita-ddns [--config PATH] {server,cli} ...")
        return 0

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.mode == "server":
        if remaining:
            print(
                f"Unrecognized server argument(s): {' '.join(remaining)}",
                file=sys.stderr,
            )
            return 2
        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)
        try:
            asyncio.run(main_server_loop(config))
            return 0
        except KeyboardInterrupt:
            return 130
        except Exception:
            log.exception("Server terminated unexpectedly")
            return 1

    cli_parser = setup_cli_parser()
    cli_args = cli_parser.parse_args(remaining)
    try:
        default_identity = load_or_create_identity(
            os.path.join(config["storage_path"], "akita_identity")
        )
        ensure_network_id(config, default_identity)
        if cli_args.command == "list":
            return run_cli(cli_args, config)
        reticulum = ret.Reticulum(configdir=config["storage_path"])
        return run_cli(cli_args, config, reticulum)
    except Exception as exc:
        print(f"Client startup error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
