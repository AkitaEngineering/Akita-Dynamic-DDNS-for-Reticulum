# akita_ddns/cli.py
import argparse
import logging
import sys
import time
import threading
import textwrap
from typing import Dict, Any, Optional

import reticulum as ret

# Assume these modules are siblings in the package
from .config import get_config
from .utils import parse_name
from .crypto import generate_signature # Only need generate
from .network import APP_NAME, ASPECT_RESPONSE, ASPECT_BROADCAST # Import constants

# Use logger specific to this module
log = logging.getLogger(__name__)

# --- Globals for Resolve Response Handling ---
# Use a dictionary to store response data associated with a request key (e.g., "namespace:name")
_resolve_responses: Dict[str, Dict[str, Any]] = {}
_resolve_lock = threading.Lock() # Protects access to the shared dictionaries
_response_events: Dict[str, threading.Event] = {} # One event per unique resolve request

def _cli_response_callback(packet_hash, packet_interface):
    """Callback for handling RESOLVE responses in the CLI."""
    global _resolve_responses, _response_events
    packet = packet_interface.packet
    if not packet or not packet.plaintext:
        log.debug("CLI received empty response packet.")
        return # Ignore empty packets

    try:
        resp_data = packet.plaintext.decode("utf-8")
        parts = resp_data.split(":")
        # Expected format: RESPONSE:namespace:name:resolved_rid_hex
        if len(parts) == 4 and parts[0] == "RESPONSE":
            namespace, name, resolved_rid_hex = parts[1], parts[2], parts[3]
            request_key = f"{namespace}:{name}" # Key to match request

            log.info(f"CLI received resolution: {namespace}@{name} -> {resolved_rid_hex}")

            with _resolve_lock:
                # Store the response data, overwriting previous if any
                _resolve_responses[request_key] = {
                    "rid": resolved_rid_hex,
                    "received_at": time.time()
                }
                # Signal the corresponding event if it exists
                event = _response_events.get(request_key)
                if event:
                    event.set() # Signal that *a* response for this key was received
        else:
             log.debug(f"CLI received non-RESPONSE or malformed packet: {resp_data}")

    except Exception as e:
        log.warning(f"Error processing potential response packet in CLI: {e}", exc_info=True)


def _print_state(state_dict: Dict, title: str):
     """Helper to print dictionary-based state nicely."""
     print(f"\n--- {title} ---")
     if not state_dict:
          print(" (empty)")
          return

     # Sort outer keys for consistent output
     for key in sorted(state_dict.keys()):
          value = state_dict[key]
          if isinstance(value, dict):
               # Sort inner keys too
               print(f" {key}:")
               if not value:
                    print("  (empty)")
                    continue
               for sub_key in sorted(value.keys()):
                    sub_value = value[sub_key]
                    # Format specific types nicely
                    if title.startswith("Local Registry") and isinstance(sub_value, tuple) and len(sub_value) == 4: # Registry Entry
                         rid, ts, sig, exp = sub_value
                         status = "active" if time.time() < exp else "expired"
                         expires_in = exp - time.time()
                         expires_str = f"{expires_in:.0f}s" if expires_in > 0 else "expired"
                         print(f"  - {sub_key}:")
                         print(f"      RID: {rid.hex()}")
                         print(f"      Registered: {time.ctime(ts)}")
                         print(f"      Expires:    {time.ctime(exp)} ({expires_str})")
                         # print(f"      Signature: {sig.hex()}") # Too verbose usually
                    elif title.startswith("Local Cache") and isinstance(sub_value, tuple) and len(sub_value) == 2: # Cache Entry
                         rid, ts = sub_value
                         print(f"  - {sub_key}: RID={rid.hex()}, CachedAt={time.ctime(ts)}")
                    else:
                         print(f"  - {sub_key}: {sub_value}")
          else:
               # For simple key-value pairs (like namespaces, reputation)
               print(f" {key}: {value}")
     print(f"--- End {title} ---")


def run_cli(args: argparse.Namespace, config: Dict[str, Any], reticulum_instance: ret.Reticulum):
    """Executes the appropriate CLI command."""
    global _resolve_responses, _response_events

    # --- Get Identity for CLI actions ---
    cli_identity: Optional[ret.Identity] = None
    # Determine which identity argument to use based on command
    identity_arg_name = None
    if args.command == 'register':
        identity_arg_name = 'identity'
    elif args.command == 'resolve':
         identity_arg_name = 'identity' # Needed for listening
    elif args.command == 'create_namespace':
        identity_arg_name = 'owner_identity'
    # No identity needed for 'list' command

    identity_path = getattr(args, identity_arg_name) if identity_arg_name else None

    try:
        if identity_path:
            cli_identity = ret.Identity.from_file(identity_path)
            if not cli_identity:
                # Use print for CLI user feedback, log for internal logs
                print(f"Error: Could not load identity from {identity_path}", file=sys.stderr)
                sys.exit(1)
            log.info(f"Using identity from file: {identity_path} ({cli_identity.hash.hex()})")
        elif identity_arg_name: # Only get default if an identity is needed for the command
            # Use default Reticulum identity
            cli_identity = reticulum_instance.get_identity()
            if not cli_identity:
                # Create ephemeral identity if no default exists
                log.warning("No default Reticulum identity found or specified, creating ephemeral one for CLI.")
                print("Warning: No default Reticulum identity found, using ephemeral one.", file=sys.stderr)
                cli_identity = ret.Identity()
                # Don't set it as default in the instance, just use it
            log.info(f"Using default/ephemeral identity: {cli_identity.hash.hex()}")

        # Check if we have an identity if one is required by the command
        if identity_arg_name and not cli_identity:
             print(f"Error: Failed to obtain an identity for command '{args.command}'. Use --{identity_arg_name} or ensure a default identity exists.", file=sys.stderr)
             sys.exit(1)

    except Exception as e:
        print(f"Error initializing identity for CLI: {e}", file=sys.stderr)
        sys.exit(1)

    # --- Define Destinations needed for CLI (only if not 'list' command) ---
    broadcast_dest = None
    response_dest = None
    if args.command != 'list':
        try:
            akita_namespace_hash = bytes.fromhex(config["akita_namespace_identity_hash"])

            # Destination for sending commands (REGISTER, RESOLVE, NAMESPACE_CREATE)
            # Use the shared network identity hash as the target
            broadcast_dest = ret.Destination(
                ret.Identity(identity_hash=akita_namespace_hash),
                ret.Destination.OUT,
                ret.Destination.BROADCAST,
                APP_NAME,
                ASPECT_BROADCAST # Send to the server's broadcast aspect
            )

            # Destination for receiving RESOLVE responses (only if resolving)
            if args.command == 'resolve':
                if not cli_identity: # Should have been caught above, but double check
                     print("Internal Error: Missing identity for resolve listener.", file=sys.stderr)
                     sys.exit(1)
                response_dest = ret.Destination(
                    cli_identity, # Listen using our CLI identity
                    ret.Destination.IN,
                    ret.Destination.SINGLE, # Expect direct responses
                    APP_NAME,
                    ASPECT_RESPONSE # Listen on the response aspect
                )
                response_dest.set_proof_strategy(ret.Destination.PROVE_NONE) # Don't require proof for responses
                # Register callback AFTER destination is fully configured
                response_dest.register_incoming_callback(_cli_response_callback)
                log.info(f"Listening for responses on destination: {response_dest.hash.hex()}")

        except Exception as e:
            print(f"Error setting up Reticulum destinations for CLI: {e}", file=sys.stderr)
            sys.exit(1)


    # --- Execute Command Logic ---
    if args.command == "register":
        # Ensure required objects are available
        if not broadcast_dest or not cli_identity:
             print("Internal Error: Missing destination or identity for register.", file=sys.stderr)
             sys.exit(1)
        try:
            # Use the configured hash as the default namespace "name"
            default_ns = config["akita_namespace_identity_hash"]
            name, namespace = parse_name(args.name, default_ns)
            rid_to_register = bytes.fromhex(args.rid) if args.rid else cli_identity.hash # Default to own hash
            ttl = args.ttl if args.ttl is not None else config["default_ttl"]
            if ttl <= 0: raise ValueError("TTL must be positive")

            print(f"Registering '{name}' in namespace '{namespace}' to {rid_to_register.hex()} with TTL {ttl}...")

            # Prepare message
            data_to_sign = f"{namespace}:{name}:{rid_to_register.hex()}:{ttl}".encode("utf-8")
            signature = generate_signature(data_to_sign, cli_identity)
            if not signature:
                 print("Error: Failed to generate signature for registration.", file=sys.stderr)
                 sys.exit(1)

            # Format: REGISTER:namespace:name:rid_hex:identity_hash_hex:signature_hex:ttl
            message = f"REGISTER:{namespace}:{name}:{rid_to_register.hex()}:{cli_identity.hash.hex()}:{signature.hex()}:{ttl}".encode("utf-8")

            # Send packet
            packet = ret.Packet(broadcast_dest, message)
            if packet.send():
                print("Registration message sent.")
                # Give a little time for packet to potentially traverse network
                time.sleep(0.5)
            else:
                 # Reticulum packet.send() returns None if path is unavailable or send failed
                 print("Error: Failed to send registration message (is Reticulum running? Any peers?).", file=sys.stderr)
                 sys.exit(1) # Exit with error if send fails

        except ValueError as e:
            print(f"Error: Invalid input - {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during registration: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "resolve":
        # Ensure required objects are available
        if not broadcast_dest or not response_dest or not cli_identity:
             print("Internal Error: Missing destination or identity for resolve.", file=sys.stderr)
             sys.exit(1)
        try:
            default_ns = config["akita_namespace_identity_hash"]
            name, namespace = parse_name(args.name, default_ns)
            timeout = args.timeout
            request_key = f"{namespace}:{name}" # Unique key for this request

            print(f"Resolving '{name}' in namespace '{namespace}'...")

            # Prepare for response: clear old data and set up event for this specific request
            with _resolve_lock:
                _resolve_responses.pop(request_key, None) # Clear previous response for this key
                event = threading.Event()
                _response_events[request_key] = event
                event.clear()


            # Prepare and send resolve request
            # Format: RESOLVE:namespace:name:requester_rid_hex
            message = f"RESOLVE:{namespace}:{name}:{cli_identity.hash.hex()}".encode("utf-8")
            packet = ret.Packet(broadcast_dest, message)

            if not packet.send():
                print("Error: Failed to send resolve request (is Reticulum running? Any peers?).", file=sys.stderr)
                # Clean up event
                with _resolve_lock: _response_events.pop(request_key, None)
                sys.exit(1)

            # Wait for response or timeout
            print(f"Waiting for response (up to {timeout} seconds)...")
            resolved_rid = None
            # Use the specific event for this request
            if event.wait(timeout=timeout):
                 # Event was set, check if the response is stored for our key
                 with _resolve_lock:
                      response_data = _resolve_responses.get(request_key)
                 if response_data:
                    resolved_rid = response_data.get("rid")
                    print(f"Resolved '{args.name}' to RID: {resolved_rid}")
                 else:
                    # Should not happen if event was set correctly, but handle anyway
                    print("Resolution failed (response event triggered, but no data found).")
                    sys.exit(1)
            else:
                print("Resolution failed (timeout).")
                sys.exit(1) # Exit with error on timeout

            # Clean up event and response data for this request
            with _resolve_lock:
                _response_events.pop(request_key, None)
                _resolve_responses.pop(request_key, None)


        except ValueError as e:
            print(f"Error: Invalid input - {e}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error during resolution: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "create_namespace":
        # Ensure required objects are available
        if not broadcast_dest or not cli_identity:
             print("Internal Error: Missing destination or identity for create_namespace.", file=sys.stderr)
             sys.exit(1)
        try:
            namespace = args.namespace
            owner_identity = cli_identity # Already loaded

            # Validate namespace name
            if not namespace or '.' in namespace or not namespace.strip():
                 print("Error: Invalid namespace name. Cannot be empty, whitespace, or contain '.'", file=sys.stderr)
                 sys.exit(1)
            namespace = namespace.strip() # Use stripped version

            print(f"Requesting creation of namespace '{namespace}' with owner {owner_identity.hash.hex()}...")

            owner_hash_hex = owner_identity.hash.hex()
            # Format signed: NAMESPACE_CREATE:namespace:owner_hash_hex
            data_to_sign = f"NAMESPACE_CREATE:{namespace}:{owner_hash_hex}".encode("utf-8")
            signature = generate_signature(data_to_sign, owner_identity)
            if not signature:
                print("Error: Failed to generate signature for namespace creation.", file=sys.stderr)
                sys.exit(1)

            # Format sent: NAMESPACE_CREATE:namespace:owner_hash_hex:signature_hex
            message = f"{data_to_sign.decode('utf-8')}:{signature.hex()}".encode("utf-8")
            packet = ret.Packet(broadcast_dest, message)

            if packet.send():
                print("Namespace creation request sent.")
                time.sleep(0.5) # Allow time for propagation
            else:
                 print("Error: Failed to send namespace creation request (is Reticulum running? Any peers?).", file=sys.stderr)
                 sys.exit(1)

        except Exception as e:
            print(f"Error creating namespace: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "list":
         # This command reads local state files directly
         print("Listing local Akita state (requires persistence enabled)...")
         if not config.get("persist_state"):
              print("Error: Persistence is disabled in configuration. Cannot list state.", file=sys.stderr)
              sys.exit(1)

         # Dynamically import storage here to avoid circular dependencies if cli is imported elsewhere
         try:
              from .storage import PersistentStorage
         except ImportError:
              print("Internal Error: Could not import storage module.", file=sys.stderr)
              sys.exit(1)

         storage = PersistentStorage(config)
         something_listed = False

         if args.registry:
              reg_data = storage.load_registry()
              # Need Registry class to interpret the data structure correctly for printing
              # For simplicity, just dump the raw loaded data for now
              # Or instantiate a temporary registry to use its printing logic?
              # Let's just print raw loaded data:
              print("\n--- Persisted Registry State ---")
              if not reg_data: print(" (empty or not found)")
              else: print(yaml.dump(reg_data, allow_unicode=True, default_flow_style=False))
              something_listed = True
         # Cache listing removed as it's in-memory only
         # if args.cache: ...
         if args.namespaces:
              ns_data = storage.load_namespaces()
              _print_state(ns_data, "Persisted Namespace Ownership State")
              something_listed = True
         if args.reputation:
              rep_data = storage.load_reputation()
              _print_state(rep_data, "Persisted Reputation State")
              something_listed = True

         if not something_listed:
              print("\nNo state type specified to list.")
              print("Use --registry, --namespaces, or --reputation flag.")


def setup_cli_parser() -> argparse.ArgumentParser:
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(
        description="Akita DDNS CLI - Interact with the Akita network or list local state.",
        formatter_class=argparse.RawTextHelpFormatter # Preserve formatting in help
    )
    # Subparsers for each command
    subparsers = parser.add_subparsers(dest="command", help="Command to execute", required=True)

    # --- Register command ---
    parser_register = subparsers.add_parser("register", help="Register or update a name on the network.")
    parser_register.add_argument("--name", required=True, help="Fully qualified name (e.g., my-device.mynamespace or my-device if using default namespace)")
    parser_register.add_argument("--rid", help="Specific RID (hex) to register. Defaults to the sending identity's hash.")
    parser_register.add_argument("--ttl", type=int, help="Time-to-live in seconds (default: from server config)")
    parser_register.add_argument("--identity", help="Path to the Reticulum identity file to use for signing.\nDefaults to Reticulum's default identity.")

    # --- Resolve command ---
    parser_resolve = subparsers.add_parser("resolve", help="Resolve a name to an RID using the network.")
    parser_resolve.add_argument("--name", required=True, help="Fully qualified name to resolve (e.g., my-device.mynamespace)")
    parser_resolve.add_argument("--timeout", type=float, default=5.0, help="Resolution timeout in seconds (default: 5.0)")
    parser_resolve.add_argument("--identity", help="Path to the Reticulum identity file to use (for listening to the response).\nDefaults to Reticulum's default identity.")

    # --- Create Namespace command ---
    parser_create_ns = subparsers.add_parser("create_namespace", help="Create a new namespace owned by an identity on the network.")
    parser_create_ns.add_argument("--namespace", required=True, help="Name of the namespace to create (cannot contain '.')")
    parser_create_ns.add_argument("--owner_identity", help="Path to the Reticulum identity file of the owner.\nDefaults to Reticulum's default identity.")

    # --- List command ---
    parser_list = subparsers.add_parser("list", help="List locally persisted state (requires persistence enabled in config).")
    parser_list.add_argument("--registry", action="store_true", help="List persisted registry entries.")
    # Cache listing removed as it's in-memory only
    # parser_list.add_argument("--cache", action="store_true", help="List cache entries (Note: Cache is in-memory only).")
    parser_list.add_argument("--namespaces", action="store_true", help="List persisted namespace ownership.")
    parser_list.add_argument("--reputation", action="store_true", help="List persisted reputation scores.")


    return parser
