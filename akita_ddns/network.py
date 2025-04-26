# akita_ddns/network.py
import asyncio
import logging
import random
import time
import yaml
from typing import Dict, Any, Optional, Tuple

import reticulum as ret

from .config import get_config
from .storage import Registry, Cache, RegistryEntry # Import type alias
from .namespace import NamespaceManager
from .reputation import ReputationManager
from .crypto import generate_signature, verify_signature
from .utils import RateLimiter, parse_name

# Use logger specific to this module
log = logging.getLogger(__name__)

# Define constants for Reticulum app name and aspects for clarity
APP_NAME = "akita_ddns"
ASPECT_BROADCAST = "broadcast" # For register, update, gossip, namespace_create, resolve requests
ASPECT_RESPONSE = "response"   # For resolve responses ONLY

class AkitaServer:
    """Handles Reticulum network interactions for the Akita DDNS server."""

    def __init__(self, reticulum_instance: ret.Reticulum,
                 registry: Registry, cache: Cache,
                 namespace_manager: NamespaceManager,
                 reputation_manager: ReputationManager):
        self.reticulum = reticulum_instance
        self.config = get_config()
        self.registry = registry
        self.cache = cache
        self.namespace_manager = namespace_manager
        self.reputation_manager = reputation_manager

        # Initialize Rate Limiter with configured rate and some burst capacity
        rate_limit = self.config.get("rate_limit_requests_per_sec", 10.0)
        self.rate_limiter = RateLimiter(rate_limit, rate_limit * 2)

        self.server_identity = self.reticulum.get_identity()
        if not self.server_identity:
             # This should be caught in main.py, but double-check
             raise RuntimeError("Reticulum instance must have a default identity set for AkitaServer.")
        log.info(f"AkitaServer using identity: {self.server_identity.hash.hex()}")

        # Validate and store the Akita network hash
        try:
             self.akita_namespace_hash = bytes.fromhex(self.config["akita_namespace_identity_hash"])
             log.info(f"Akita network hash: {self.config['akita_namespace_identity_hash']}")
        except (ValueError, TypeError) as e:
             log.critical(f"Invalid Akita Namespace Identity Hash in config: {self.config['akita_namespace_identity_hash']} - {e}")
             raise ValueError("Invalid akita_namespace_identity_hash configuration") from e

        # --- Define Reticulum Destinations ---
        # Main listener for broadcast messages
        self.akita_listener_destination = ret.Destination(
            ret.Identity(identity_hash=self.akita_namespace_hash), # Listen using the shared network hash
            ret.Destination.IN,
            ret.Destination.BROADCAST,
            APP_NAME,
            ASPECT_BROADCAST
        )
        self.akita_listener_destination.set_proof_strategy(ret.Destination.PROVE_NONE)
        # Register callback AFTER all attributes are initialized
        self.akita_listener_destination.register_incoming_callback(self._handle_incoming_packet)
        log.info(f"Akita Listener Destination registered: {self.akita_listener_destination.hash.hex()} ({APP_NAME}/{ASPECT_BROADCAST})")

        # Destination for sending broadcasts (used for Gossip primarily)
        self._broadcast_sender_destination = ret.Destination(
            ret.Identity(identity_hash=self.akita_namespace_hash), # Target the shared network hash
            ret.Destination.OUT,
            ret.Destination.BROADCAST,
            APP_NAME,
            ASPECT_BROADCAST
        )
        log.debug(f"Akita Broadcast Sender configured for destination hash: {self._broadcast_sender_destination.hash.hex()}")

        # Response Destination Template (used for sending RESOLVE responses)
        self._response_dest_template = ret.Destination(
             None, # Identity will be set per recipient
             ret.Destination.OUT,
             ret.Destination.SINGLE, # Send directly to requester
             APP_NAME,
             ASPECT_RESPONSE # Send on the response aspect
        )
        log.debug("Akita Response Sender Template configured.")

        # Flag to signal shutdown for async tasks
        self._shutdown_requested = False


    def _handle_incoming_packet(self, packet_hash, packet_interface):
        """Callback function for Reticulum to handle incoming packets on the Akita broadcast destination."""
        if self._shutdown_requested:
             log.debug("Shutdown requested, ignoring incoming packet.")
             return

        # 1. Rate Limit Check FIRST
        if not self.rate_limiter.check():
            # Logged within RateLimiter.check()
            return

        # 2. Basic Packet Validation
        if not packet_interface or not packet_interface.packet:
            log.warning("Received invalid packet interface or packet object.")
            return

        packet = packet_interface.packet
        sender_identity_hash = packet.source_hash

        if not sender_identity_hash:
            # Should not happen with modern Reticulum unless maybe over unauthenticated interface?
            log.warning("Received packet with no source hash. Ignoring.")
            return

        # Ignore packets sent by self
        if sender_identity_hash == self.server_identity.hash:
             log.debug("Ignoring packet sent by self.")
             return

        try:
            # 3. Decode Payload
            # Use packet.plaintext which is automatically decrypted if link was encrypted
            data = packet.plaintext.decode("utf-8")
            parts = data.split(":", 1) # Split only on the first colon (Command:Payload)
            command = parts[0].upper() # Normalize command to uppercase
            payload = parts[1] if len(parts) > 1 else ""

            log.debug(f"Received command '{command}' (payload len={len(payload)}) from {sender_identity_hash.hex()}")

            # 4. Dispatch Command to Specific Handler
            handler_method = getattr(self, f"_handle_{command.lower()}", None)
            if handler_method and callable(handler_method):
                 # Pass the raw packet object as well, handler might need more context (like interface)
                 handler_method(payload, sender_identity_hash, packet)
            else:
                log.warning(f"Received unknown command '{command}' from {sender_identity_hash.hex()}")
                self.reputation_manager.update_reputation(sender_identity_hash, -2) # Penalize unknown commands

        except UnicodeDecodeError:
            log.error(f"Could not decode packet content as UTF-8 from {sender_identity_hash.hex()}.")
            self.reputation_manager.update_reputation(sender_identity_hash, -2) # Penalize malformed encoding
        except Exception as e:
            # Catch unexpected errors during packet processing
            log.error(f"Unexpected error handling packet from {sender_identity_hash.hex()}: {e}", exc_info=True)
            # Avoid penalizing reputation for internal server errors


    def _handle_register(self, payload: str, sender_hash: bytes, packet: ret.Packet):
        """Handles REGISTER and UPDATE commands (treated identically server-side)."""
        # Format: namespace:name:rid_hex:identity_hash_hex:signature_hex:ttl
        try:
            parts = payload.split(":", 5)
            if len(parts) != 6:
                raise ValueError("Incorrect number of parts for REGISTER/UPDATE")

            namespace, name, rid_hex, identity_hash_hex, signature_hex, ttl_str = parts

            # --- Input Validation ---
            # Use parse_name to validate/normalize name and namespace
            # Note: We don't have a default namespace here, the one from the packet IS the namespace.
            # We could validate the namespace part against allowed characters if needed.
            if not name.strip() or not namespace.strip():
                 raise ValueError("Empty name or namespace part")
            name = name.strip()
            namespace = namespace.strip()
            if '.' in namespace: # Prevent ambiguity
                 raise ValueError("Namespace cannot contain '.'")

            rid = bytes.fromhex(rid_hex)
            identity_hash = bytes.fromhex(identity_hash_hex)
            signature = bytes.fromhex(signature_hex)
            ttl = int(ttl_str)
            if ttl <= 0:
                 raise ValueError("TTL must be positive")

            # --- Security Checks ---
            # Check 1: Claimed identity matches packet sender
            if identity_hash != sender_hash:
                 log.warning(f"REGISTER/UPDATE identity hash mismatch: packet sender {sender_hash.hex()} != message identity {identity_hash.hex()}. Dropping.")
                 return

            # Check 2: Verify signature
            data_to_verify = f"{namespace}:{name}:{rid_hex}:{ttl}".encode("utf-8")
            if not verify_signature(data_to_verify, signature, identity_hash):
                log.warning(f"REGISTER/UPDATE signature verification failed for {name}@{namespace} from {identity_hash.hex()}")
                self.reputation_manager.update_reputation(sender_hash, -1) # Penalize bad signature
                return

            # Check 3: Check namespace ownership
            # The identity *whose RID is being registered* must own the namespace,
            # OR the namespace must be unowned.
            if not self.namespace_manager.is_authorized(namespace, rid):
                 log.warning(f"REGISTER/UPDATE denied for '{name}' in owned namespace '{namespace}' by non-owner {rid.hex()}. Sender was {sender_hash.hex()}.")
                 self.reputation_manager.update_reputation(sender_hash, -1) # Penalize attempt by sender
                 return

            # --- Action ---
            # If all checks pass, register the name
            registration_time = time.time() # Use current time as registration time
            expiration_time = registration_time + ttl
            success = self.registry.register(namespace, name, rid, registration_time, signature, expiration_time)

            if success:
                 # Reward sender for successful registration
                 self.reputation_manager.update_reputation(sender_hash, 1)
            # No else needed as registry.register logs errors internally

        except (ValueError, TypeError) as e:
            log.error(f"Error parsing REGISTER/UPDATE payload '{payload}' from {sender_hash.hex()}: {e}")
            self.reputation_manager.update_reputation(sender_hash, -1) # Penalize malformed message


    def _handle_resolve(self, payload: str, sender_hash: bytes, packet: ret.Packet):
        """Handles RESOLVE commands."""
        # Format: namespace:name:requester_rid_hex (requester_rid must match sender_hash)
        try:
            parts = payload.split(":", 2)
            if len(parts) != 3:
                raise ValueError("Incorrect number of parts for RESOLVE")

            namespace, name, requester_rid_hex = parts

            # --- Input Validation ---
            # Use parse_name to validate/normalize name and namespace
            if not name.strip() or not namespace.strip():
                 raise ValueError("Empty name or namespace part")
            name = name.strip()
            namespace = namespace.strip()

            requester_rid = bytes.fromhex(requester_rid_hex)

            # --- Security Check ---
            # Ensure requester RID matches packet sender hash
            if requester_rid != sender_hash:
                log.warning(f"RESOLVE requester RID mismatch: packet sender {sender_hash.hex()} != message RID {requester_rid.hex()}. Dropping.")
                return

            # --- Action ---
            # Attempt to resolve locally (checks cache first, then registry)
            resolved_rid = self.cache.get(namespace, name)
            if not resolved_rid:
                 # Cache miss or expired, check registry
                 registry_result: Optional[RegistryEntry] = self.registry.resolve(namespace, name) # Checks TTL
                 if registry_result:
                     # Found in registry, extract RID and add to cache
                     resolved_rid = registry_result[0] # Index 0 is the RID
                     self.cache.put(namespace, name, resolved_rid)
                     log.debug(f"Resolve: Cache updated for {name}@{namespace} from registry.")

            # If we have a resolved RID (from cache or registry)
            if resolved_rid:
                resolved_rid_hex = resolved_rid.hex()
                response_payload = f"RESPONSE:{namespace}:{name}:{resolved_rid_hex}".encode("utf-8")
                log.info(f"Sending resolution for '{name}'@{namespace} -> {resolved_rid_hex} back to {sender_hash.hex()}")

                # Send response back to the requester using the response aspect
                try:
                    # Create the destination dynamically for the specific recipient
                    recipient_identity = ret.Identity(identity_hash=sender_hash)
                    response_dest = ret.Destination(
                        recipient_identity,
                        self._response_dest_template.direction,
                        self._response_dest_template.type,
                        self._response_dest_template.app_name,
                        self._response_dest_template.aspects # Use aspects from template ('response')
                    )
                    response_dest.set_proof_strategy(ret.Destination.PROVE_NONE) # No proof needed for response

                    response_packet = ret.Packet(response_dest, response_payload)
                    if not response_packet.send():
                         # Path might not be known, this is normal in Reticulum
                         log.warning(f"Failed to send RESOLVE response to {sender_hash.hex()}. Path likely unavailable.")
                    else:
                         log.debug(f"Successfully sent RESOLVE response to {sender_hash.hex()}")
                         # Maybe reward slightly for successful interaction?
                         # self.reputation_manager.update_reputation(sender_hash, 1)

                except Exception as e:
                    # Handle errors during identity creation or packet sending
                    log.error(f"Error creating/sending RESOLVE response to {sender_hash.hex()}: {e}", exc_info=True)

            else:
                # Name not found locally or expired
                log.info(f"Resolution failed locally for '{name}'@{namespace} requested by {sender_hash.hex()}")
                # Do NOT send a "Not Found" response. Silence is the standard behavior.
                # Don't penalize the requester for a failed resolve.

        except (ValueError, TypeError) as e:
            log.error(f"Error parsing RESOLVE payload '{payload}' from {sender_hash.hex()}: {e}")
            self.reputation_manager.update_reputation(sender_hash, -1) # Penalize malformed message


    def _handle_gossip(self, payload: str, sender_hash: bytes, packet: ret.Packet):
        """Handles GOSSIP commands."""
        # Format: {yaml_dump_of_registry_with_hex}
        log.debug(f"Processing GOSSIP message (len={len(payload)}) from {sender_hash.hex()}")
        try:
            gossip_data_serializable = yaml.safe_load(payload)
            if not isinstance(gossip_data_serializable, dict):
                 raise ValueError("Gossip payload is not a dictionary")

            # Convert hex strings back to bytes for RIDs and signatures
            processed_gossip_registry: Dict[str, Dict[str, RegistryEntry]] = {}
            invalid_entries_skipped = 0
            for ns, names in gossip_data_serializable.items():
                processed_names = {}
                if not isinstance(names, dict): # Validate inner structure
                     log.warning(f"Invalid format for namespace '{ns}' in gossip from {sender_hash.hex()} (expected dict). Skipping.")
                     invalid_entries_skipped += 1 # Penalize for bad structure
                     continue
                for nm, entry in names.items():
                    try:
                        # Entry format from gossip: (rid_hex, ts, sig_hex, exp)
                        if not isinstance(entry, (list, tuple)) or len(entry) != 4:
                             raise TypeError("Invalid entry format - expected list/tuple of length 4")
                        rid_hex, ts_float, sig_hex, exp_float = entry
                        # Validate types before conversion
                        if not isinstance(rid_hex, str) or not isinstance(sig_hex, str) or \
                           not isinstance(ts_float, (int, float)) or not isinstance(exp_float, (int, float)):
                            raise TypeError("Invalid types within gossip entry tuple")

                        processed_names[nm] = (bytes.fromhex(rid_hex), float(ts_float), bytes.fromhex(sig_hex), float(exp_float))
                    except (ValueError, TypeError, IndexError) as e:
                        log.warning(f"Skipping invalid entry format/content in gossip data for {nm}@{ns} from {sender_hash.hex()}: {e}")
                        invalid_entries_skipped += 1
                        continue # Skip this entry
                if processed_names: # Only add namespace if it has valid entries
                    processed_gossip_registry[ns] = processed_names

            if invalid_entries_skipped > 0:
                 # Penalize sender for sending badly formatted gossip entries
                 self.reputation_manager.update_reputation(sender_hash, -1 * invalid_entries_skipped)

            if not processed_gossip_registry:
                 log.debug(f"Gossip message from {sender_hash.hex()} contained no valid entries after processing.")
                 return # Nothing to do

            # Pass to registry for processing (verifies signatures, ownership, timestamps)
            current_owners = self.namespace_manager.get_owners() # Get current owners for validation
            new_count, updated_count = self.registry.process_gossip(processed_gossip_registry, current_owners, sender_hash)

            # Update reputation based on usefulness of gossip
            if new_count > 0 or updated_count > 0:
                # Reward sender for providing useful information
                self.reputation_manager.update_reputation(sender_hash, 1)
            else:
                # Sender sent valid gossip, but we didn't learn anything new. No penalty/reward.
                log.debug(f"Received gossip from {sender_hash.hex()}, but no new/updated information was added.")

        except yaml.YAMLError as e:
            log.error(f"Error parsing GOSSIP YAML data from {sender_hash.hex()}: {e}")
            self.reputation_manager.update_reputation(sender_hash, -2) # Penalize significantly for invalid YAML
        except (ValueError, TypeError) as e:
             log.error(f"Error processing GOSSIP payload structure from {sender_hash.hex()}: {e}")
             self.reputation_manager.update_reputation(sender_hash, -1) # Penalize malformed structure
        except Exception as e:
             log.error(f"Unexpected error processing GOSSIP data from {sender_hash.hex()}: {e}", exc_info=True)
             # Avoid penalizing reputation for internal server errors


    def _handle_namespace_create(self, payload: str, sender_hash: bytes, packet: ret.Packet):
        """Handles NAMESPACE_CREATE commands."""
        # Format: namespace:owner_hash_hex:signature_hex
        try:
            parts = payload.split(":", 2)
            if len(parts) != 3:
                raise ValueError("Incorrect number of parts for NAMESPACE_CREATE")

            namespace, owner_hash_hex, signature_hex = parts

            # --- Input Validation ---
            if not namespace.strip() or '.' in namespace:
                 raise ValueError("Invalid namespace name (empty or contains '.')")
            namespace = namespace.strip()

            owner_hash = bytes.fromhex(owner_hash_hex)
            signature = bytes.fromhex(signature_hex)

            # --- Security Check ---
            # Ensure owner hash claimed in message matches packet sender hash
            if owner_hash != sender_hash:
                log.warning(f"NAMESPACE_CREATE owner hash mismatch: packet sender {sender_hash.hex()} != message owner {owner_hash.hex()}. Dropping.")
                return

            # --- Action ---
            # Pass to namespace manager for processing (verifies signature, checks conflicts)
            success = self.namespace_manager.create_namespace(namespace, owner_hash, signature)

            # Update reputation based on success/failure
            if success:
                # Reward sender for successful creation/confirmation
                self.reputation_manager.update_reputation(sender_hash, 1)
            else:
                 # Penalize failed/conflicting creation attempt
                 self.reputation_manager.update_reputation(sender_hash, -1)

        except (ValueError, TypeError) as e:
            log.error(f"Error parsing NAMESPACE_CREATE payload '{payload}' from {sender_hash.hex()}: {e}")
            self.reputation_manager.update_reputation(sender_hash, -1) # Penalize malformed message


    async def run_gossip_loop(self):
        """Coroutine that periodically sends gossip messages."""
        # Wait a bit initially for the network to stabilize and state to load
        await asyncio.sleep(random.uniform(5, 15))
        log.info("Starting gossip loop...")

        while not self._shutdown_requested:
            interval = self.config.get("gossip_interval", 120)
            # Add random jitter (+/- 10%) to avoid synchronized flooding
            sleep_time = interval + random.uniform(-interval * 0.1, interval * 0.1)
            log.debug(f"Gossip loop: Sleeping for {sleep_time:.2f} seconds.")
            try:
                 await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                 log.info("Gossip loop cancelled during sleep.")
                 break # Exit loop if cancelled

            if self._shutdown_requested: break # Check again after sleep

            try:
                # Get current valid registry entries
                registry_to_gossip = self.registry.get_registry_for_gossip()
                if not registry_to_gossip:
                    log.debug("Gossip loop: Registry is empty or has no valid entries, skipping gossip cycle.")
                    continue

                # Prepare registry data for gossip (convert bytes to hex)
                gossip_data_serializable = {}
                for ns, names in registry_to_gossip.items():
                    serializable_names = {}
                    for nm, (rid, ts, sig, exp) in names.items():
                         try:
                              serializable_names[nm] = (rid.hex(), ts, sig.hex(), exp)
                         except Exception as e:
                              # Should not happen if data in registry is valid bytes
                              log.warning(f"Skipping serialization of gossip entry {nm}@{ns} due to error: {e}")
                    if serializable_names:
                        gossip_data_serializable[ns] = serializable_names

                if not gossip_data_serializable:
                    log.debug("Gossip loop: No valid entries remained after serialization, skipping gossip cycle.")
                    continue

                # Serialize the prepared data to YAML
                gossip_yaml = yaml.dump(gossip_data_serializable, allow_unicode=True).encode("utf-8")
                message = b"GOSSIP:" + gossip_yaml

                log.info(f"Gossiping registry state ({len(gossip_data_serializable)} namespaces, size={len(message)} bytes)")
                packet = ret.Packet(self._broadcast_sender_destination, message)
                if not packet.send():
                    # This is common if no peers are reachable or transport is down
                    log.debug("Failed to send gossip packet (no path or peers available?).")
                else:
                     log.debug("Gossip packet sent successfully.")

            except asyncio.CancelledError:
                 log.info("Gossip loop cancelled during processing.")
                 break
            except Exception as e:
                # Catch broad exceptions to prevent the loop from crashing
                log.error(f"Error during gossip loop cycle: {e}", exc_info=True)
                # Optional: Add a longer sleep after an error to avoid rapid failure loops
                await asyncio.sleep(30) # Wait 30s after an error

        log.info("Gossip loop finished.")


    async def run_periodic_tasks(self):
        """Runs periodic maintenance tasks like TTL checks in a loop."""
        log.info("Starting periodic tasks loop (TTL checks)...")
        while not self._shutdown_requested:
            interval = self.config.get("ttl_check_interval", 600)
            # Add random jitter (+/- 10%)
            sleep_time = interval + random.uniform(-interval * 0.1, interval * 0.1)
            log.debug(f"Periodic tasks: Sleeping for {sleep_time:.2f} seconds before next TTL check.")
            try:
                 await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                 log.info("Periodic tasks loop cancelled during sleep.")
                 break # Exit loop if cancelled

            if self._shutdown_requested: break # Check again after sleep

            try:
                log.info("Running periodic TTL checks for registry and cache...")
                self.registry.run_ttl_check() # Handles its own persistence
                self.cache.run_ttl_check()
                log.info("Periodic TTL checks complete.")
            except asyncio.CancelledError:
                 log.info("Periodic tasks loop cancelled during TTL check.")
                 break
            except Exception as e:
                 # Catch broad exceptions to prevent the loop from crashing
                 log.error(f"Error during periodic TTL check: {e}", exc_info=True)
                 # Optional: Add a longer sleep after an error
                 await asyncio.sleep(30)

            # --- Add other periodic tasks here if needed ---
            # Example: Persist reputation periodically even if no updates happened?
            # try:
            #      self.reputation_manager.storage.save_reputation(self.reputation_manager.get_all_reputations())
            # except Exception as e:
            #      log.error(f"Error during periodic reputation save: {e}", exc_info=True)

        log.info("Periodic tasks loop finished.")

    def shutdown(self):
        """Signals async tasks to stop and unregisters callbacks."""
        if self._shutdown_requested: return # Already shutting down
        log.info("AkitaServer shutdown requested.")
        self._shutdown_requested = True
        # Unregister destination callback to stop processing new packets immediately
        if self.akita_listener_destination:
             self.akita_listener_destination.unregister_incoming_callback()
             log.debug("Unregistered incoming packet callback.")


    # --- Methods for sending messages (used by CLI) ---
    # Note: These are synchronous and assume Reticulum transport is active when called.

    def send_register(self, name: str, namespace: str, rid: bytes, identity: ret.Identity, ttl: int) -> bool:
        """Sends a REGISTER message to the network broadcast."""
        log.info(f"CLI sending REGISTER for '{name}'@{namespace} -> {rid.hex()} (TTL: {ttl})")
        data_to_sign = f"{namespace}:{name}:{rid.hex()}:{ttl}".encode("utf-8")
        signature = generate_signature(data_to_sign, identity)
        if not signature:
            log.error("CLI failed to generate signature for registration.")
            return False

        # Format: REGISTER:namespace:name:rid_hex:identity_hash_hex:signature_hex:ttl
        message = f"REGISTER:{namespace}:{name}:{rid.hex()}:{identity.hash.hex()}:{signature.hex()}:{ttl}".encode("utf-8")
        packet = ret.Packet(self._broadcast_sender_destination, message)
        sent = packet.send()
        if not sent:
             log.warning("CLI failed to send REGISTER packet (no path or peers?).")
        return sent

    def send_resolve_request(self, name: str, namespace: str, requester_identity: ret.Identity) -> bool:
         """Sends a RESOLVE request message to the network broadcast."""
         log.info(f"CLI sending RESOLVE request for '{name}'@{namespace} by {requester_identity.hash.hex()}")
         # Format: RESOLVE:namespace:name:requester_rid_hex
         message = f"RESOLVE:{namespace}:{name}:{requester_identity.hash.hex()}".encode("utf-8")
         packet = ret.Packet(self._broadcast_sender_destination, message)
         sent = packet.send()
         if not sent:
              log.warning("CLI failed to send RESOLVE packet (no path or peers?).")
         return sent

    def send_namespace_create_request(self, namespace: str, owner_identity: ret.Identity) -> bool:
        """Sends a NAMESPACE_CREATE request message to the network broadcast."""
        log.info(f"CLI sending NAMESPACE_CREATE request for '{namespace}' by owner {owner_identity.hash.hex()}")
        owner_hash_hex = owner_identity.hash.hex()
        # Format signed: NAMESPACE_CREATE:namespace:owner_hash_hex
        data_to_sign = f"NAMESPACE_CREATE:{namespace}:{owner_hash_hex}".encode("utf-8")
        signature = generate_signature(data_to_sign, owner_identity)
        if not signature:
            log.error("CLI failed to generate signature for namespace creation.")
            return False

        # Format sent: NAMESPACE_CREATE:namespace:owner_hash_hex:signature_hex
        message = f"{data_to_sign.decode('utf-8')}:{signature.hex()}".encode("utf-8")
        packet = ret.Packet(self._broadcast_sender_destination, message)
        sent = packet.send()
        if not sent:
             log.warning("CLI failed to send NAMESPACE_CREATE packet (no path or peers?).")
        return sent
