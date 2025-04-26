# akita_ddns/main.py
import argparse
import asyncio
import logging
import os
import sys
import signal
import threading
import time
import textwrap
from typing import Optional, List, Dict

# --- Attempt to set up Reticulum logging early ---
# This helps capture logs during Reticulum initialization itself.
# We will refine the logging setup further after loading our config.
try:
    import reticulum as ret
    # Set a basic default log level for Reticulum initially
    ret.set_loglevel(ret.loglevel.notice)
except ImportError:
     print("CRITICAL: Reticulum library not found. Please install it (`pip install reticulum`).", file=sys.stderr)
     sys.exit(1)
except Exception as e:
     print(f"CRITICAL: Error importing or setting up Reticulum: {e}", file=sys.stderr)
     sys.exit(1)


# --- Logging Setup ---
# Configure root logger early with a basic setup.
# load_config will refine it based on the config file.
logging.basicConfig(level="INFO", format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
log = logging.getLogger("akita_ddns.main") # Logger for this module

# --- Import local modules AFTER basic logging is set up ---
try:
    from .config import load_config, get_config
    from .storage import PersistentStorage, Registry, Cache
    from .namespace import NamespaceManager
    from .reputation import ReputationManager
    from .network import AkitaServer
    from .cli import setup_cli_parser, run_cli
except ImportError as e:
     # This can happen if running main.py directly without installing the package
     log.critical(f"ImportError: {e}. Make sure you are running with 'python -m akita_ddns.main ...' or have the package installed correctly.")
     sys.exit(1)


# --- Global Variables ---
stop_event = asyncio.Event() # Used to signal shutdown to async tasks
reticulum_instance: Optional[ret.Reticulum] = None
akita_server_instance: Optional[AkitaServer] = None
background_tasks: List[asyncio.Task] = [] # Keep track of running async tasks

# --- Signal Handling ---
def signal_handler(sig, frame):
    """Handles SIGINT/SIGTERM for graceful shutdown."""
    if stop_event.is_set():
        log.warning("Shutdown already in progress. Please wait or force exit.")
        return
    try: # Get signal name safely
        sig_name = signal.Signals(sig).name
    except ValueError:
        sig_name = f"Signal {sig}"
    log.warning(f"Received {sig_name}. Initiating graceful shutdown...")
    stop_event.set() # Signal async tasks to stop

    # Signal the AkitaServer instance to stop processing packets etc.
    if akita_server_instance:
        akita_server_instance.shutdown()

    # Reticulum shutdown will be handled after async tasks complete or timeout
    # We don't stop Reticulum here directly to allow async tasks to potentially
    # use it during their cleanup.

def _init_reticulum(config: Dict) -> Optional[ret.Reticulum]:
     """Initializes and returns a Reticulum instance based on config."""
     try:
        # Explicitly set log level for Reticulum based on our config
        ret_log_level_str = config.get("log_level", "INFO").lower()
        # Map common log level names to Reticulum's constants
        level_map = {
            "critical": ret.loglevel.critical,
            "error": ret.loglevel.error,
            "warning": ret.loglevel.warning,
            "notice": ret.loglevel.notice, # Reticulum specific
            "info": ret.loglevel.info,
            "verbose": ret.loglevel.verbose, # Reticulum specific
            "debug": ret.loglevel.debug,
            "trace": ret.loglevel.trace,   # Reticulum specific
        }
        ret_log_level = level_map.get(ret_log_level_str, ret.loglevel.info) # Default to info if mapping fails
        ret.set_loglevel(ret_log_level)
        log.info(f"Setting Reticulum log level to: {ret_log_level_str} ({ret_log_level})")

        r_instance = ret.Reticulum(configdir=config["storage_path"])
        log.info(f"Reticulum initialized. Storage: {config['storage_path']}")
        return r_instance
     except Exception as e:
        log.critical(f"Failed to initialize Reticulum: {e}", exc_info=True)
        return None

async def _shutdown_async_tasks(tasks: List[asyncio.Task], timeout: float = 5.0):
     """Cancels and waits for async tasks to complete with a timeout."""
     if not tasks:
          return
     log.info(f"Cancelling {len(tasks)} background task(s)...")
     for task in tasks:
          if not task.done():
               task.cancel()

     # Wait for tasks to finish cancellation with a timeout
     log.info(f"Waiting up to {timeout} seconds for tasks to finish...")
     # Use asyncio.wait to handle timeouts properly
     done, pending = await asyncio.wait(tasks, timeout=timeout, return_when=asyncio.ALL_COMPLETED)

     if pending:
          log.warning(f"{len(pending)} background task(s) did not finish within the timeout.")
          # Optionally force-cancel again or log which tasks are pending
          for task in pending:
               log.warning(f"Task still pending: {task.get_name() if hasattr(task, 'get_name') else task}")
               # task.cancel() # Might already be cancelled, but doesn't hurt
     else:
          log.info("All background tasks finished gracefully.")

     # Log exceptions from tasks that completed with errors
     for task in done:
          try:
               # If the task raised an exception, accessing result() will re-raise it
               task.result()
          except asyncio.CancelledError:
               log.debug(f"Task {task.get_name() if hasattr(task, 'get_name') else task} cancelled successfully.")
          except Exception as e:
               log.error(f"Task {task.get_name() if hasattr(task, 'get_name') else task} raised an exception: {e}", exc_info=e)


async def main_server():
    """Sets up and runs the Akita DDNS server main loop."""
    global reticulum_instance, akita_server_instance, background_tasks
    config = get_config() # Config should be loaded by main()

    log.info("Starting Akita DDNS Server...")

    # --- Initialize Reticulum ---
    reticulum_instance = _init_reticulum(config)
    if not reticulum_instance:
        sys.exit(1) # Exit if Reticulum fails

    # --- Get/Set Server Identity ---
    try:
        server_identity = reticulum_instance.get_identity()
        if not server_identity:
            log.warning("No default identity found in Reticulum storage. Creating new one.")
            server_identity = ret.Identity()
            reticulum_instance.set_identity(server_identity) # Make it the default
            log.info(f"Created and set new server identity: {server_identity.hash.hex()}")
            # Save the new identity? Reticulum usually handles this based on config path.
            # identity_path = os.path.join(config["storage_path"], "identity")
            # try: server_identity.to_file(identity_path) except Exception as e: log.error(f"Failed to save new identity: {e}")
        else:
            log.info(f"Using server identity: {server_identity.hash.hex()}")
    except Exception as e:
         log.critical(f"Failed to get/set Reticulum identity: {e}", exc_info=True)
         if reticulum_instance and hasattr(reticulum_instance, 'stop'): reticulum_instance.stop()
         sys.exit(1)


    # --- Initialize Components ---
    try:
        storage = PersistentStorage(config)
        registry = Registry(storage, config) # Loads initial state
        cache = Cache(config)
        namespace_manager = NamespaceManager(storage, config) # Loads initial state
        reputation_manager = ReputationManager(storage, config) # Loads initial state
        # Pass dependencies to the server instance
        akita_server_instance = AkitaServer(reticulum_instance, registry, cache, namespace_manager, reputation_manager)
        log.info("Server components initialized.")
    except Exception as e:
        log.critical(f"Failed to initialize server components: {e}", exc_info=True)
        if reticulum_instance and hasattr(reticulum_instance, 'stop'): reticulum_instance.stop()
        sys.exit(1)

    # --- Start Background Async Tasks ---
    log.info("Starting background tasks (Gossip, Periodic Checks)...")
    try:
         # Give tasks meaningful names for logging/debugging
         gossip_task = asyncio.create_task(akita_server_instance.run_gossip_loop(), name="GossipLoop")
         periodic_task = asyncio.create_task(akita_server_instance.run_periodic_tasks(), name="PeriodicTasks")
         background_tasks = [gossip_task, periodic_task]
    except Exception as e:
         log.critical(f"Failed to create background tasks: {e}", exc_info=True)
         if reticulum_instance and hasattr(reticulum_instance, 'stop'): reticulum_instance.stop()
         sys.exit(1)

    # --- Run until stop signal ---
    log.info("Akita server started successfully. Waiting for stop signal (Ctrl+C)...")
    try:
         await stop_event.wait() # Wait until signal_handler sets the event
    except asyncio.CancelledError:
         log.info("Main server loop cancelled externally.")
         if not stop_event.is_set(): stop_event.set() # Ensure shutdown proceeds
         if akita_server_instance: akita_server_instance.shutdown()


    # --- Initiate Shutdown ---
    log.info("Shutdown initiated.")
    await _shutdown_async_tasks(background_tasks, timeout=5.0) # Wait up to 5s for tasks

    # Reticulum shutdown is handled in the final `finally` block of main()

    log.info("Akita server asynchronous components shut down.")


def main_cli():
    """Sets up Reticulum and runs the CLI command."""
    global reticulum_instance
    config = get_config() # Load config first

    log.info("Running Akita DDNS CLI...")

    # --- Initialize Reticulum (needed for sending/receiving) ---
    # Use a minimal Reticulum setup for CLI, potentially quieter logs
    cli_log_level_str = config.get("log_level", "INFO")
    # Make CLI reticulum logs less verbose unless user set DEBUG/TRACE etc.
    # Map our level to Reticulum's levels
    level_map = { "CRITICAL": ret.loglevel.critical, "ERROR": ret.loglevel.error, "WARNING": ret.loglevel.warning, "NOTICE": ret.loglevel.notice, "INFO": ret.loglevel.info, "VERBOSE": ret.loglevel.verbose, "DEBUG": ret.loglevel.debug, "TRACE": ret.loglevel.trace }
    cli_ret_log_level = level_map.get(cli_log_level_str, ret.loglevel.error) # Default RNS logs to error for CLI

    try:
        reticulum_instance = ret.Reticulum(configdir=config["storage_path"], loglevel=cli_ret_log_level)
        log.info("Reticulum initialized for CLI.")
        # No need for UDP interface here, just transport discovery
    except Exception as e:
        print(f"Error: Failed to initialize Reticulum for CLI: {e}", file=sys.stderr)
        sys.exit(1)


    # --- Parse CLI Arguments ---
    parser = setup_cli_parser()
    # Determine the actual CLI args passed after the mode specifier ('cli')
    args_to_parse = []
    if len(sys.argv) > 1:
         # If 'cli' is the first arg after script name
         if sys.argv[1] == 'cli':
              args_to_parse = sys.argv[2:]
         # If 'server' is NOT the first arg, assume args start from argv[1]
         elif sys.argv[1] != 'server':
              args_to_parse = sys.argv[1:]
         # If 'server' is the first arg, args_to_parse remains empty (handled by server mode)

    if not args_to_parse: # No command provided after 'cli' or invalid first arg
         parser.print_help()
         # Stop Reticulum instance before exiting
         if reticulum_instance and hasattr(reticulum_instance, 'stop'): reticulum_instance.stop()
         sys.exit(0)

    try:
         args = parser.parse_args(args_to_parse)
    except SystemExit: # Handle argparse exit (e.g., on --help)
         if reticulum_instance and hasattr(reticulum_instance, 'stop'): reticulum_instance.stop()
         raise # Re-raise to exit cleanly


    # --- Run the CLI command ---
    exit_code = 0
    try:
         run_cli(args, config, reticulum_instance)
         log.info("CLI command finished.")
    except SystemExit as e:
         # Catch SystemExit to allow clean exit with specific code from run_cli
         log.info(f"CLI exited with code {e.code}.")
         exit_code = e.code or 0 # Use 0 if code is None
    except Exception as e:
         log.error(f"Error during CLI execution: {e}", exc_info=True)
         print(f"Error: An unexpected error occurred during CLI execution: {e}", file=sys.stderr)
         exit_code = 1 # Exit with error code
    finally:
        # --- Stop Reticulum instance used by CLI ---
        if reticulum_instance:
            try:
                if hasattr(reticulum_instance, 'stop'):
                    reticulum_instance.stop()
                    log.debug("Reticulum stopped after CLI execution.")
                else:
                    # Older Reticulum might not need explicit stop or lacks the method
                    pass
            except Exception as e:
                log.error(f"Error stopping Reticulum after CLI execution: {e}")
        # Exit with the determined code
        sys.exit(exit_code)


def main():
    """Main entry point dispatcher. Loads config, determines mode, and runs."""
    # Load configuration early - critical step
    try:
        config = load_config() # Load config using default path "akita_config.yaml"
    except Exception as e:
        # Logging might not be fully configured yet, print to stderr as well
        print(f"CRITICAL: Failed to load configuration: {e}", file=sys.stderr)
        log.critical(f"Failed to load configuration: {e}", exc_info=True)
        sys.exit(1) # Cannot proceed without config

    # Basic argument parsing to decide mode (server or cli)
    main_parser = argparse.ArgumentParser(
         description="Akita DDNS Server and CLI",
         formatter_class=argparse.RawTextHelpFormatter
    )
    main_parser.add_argument(
        "mode",
        choices=['server', 'cli'],
        nargs='?', # Make mode optional
        default='server', # Default to server mode if no argument given
        help=textwrap.dedent("""\
        Run mode:
          server : Start the Akita DDNS node (default).
          cli    : Execute a CLI command (see 'cli --help' for commands).
        """)
    )
    # Parse only the first argument to determine mode
    # Use parse_known_args to separate mode arg from subsequent CLI args
    args, remaining_argv = main_parser.parse_known_args()

    # Re-inject original script name and remaining args for the specific mode parser later
    # This allows 'python -m akita_ddns.main cli register --name ...' to work
    sys.argv = [sys.argv[0]] + remaining_argv

    if args.mode == 'server':
        # Setup signal handlers for graceful shutdown *before* starting the server loop
        try:
            loop = asyncio.get_event_loop()
            loop.add_signal_handler(signal.SIGINT, signal_handler, signal.SIGINT, None)
            loop.add_signal_handler(signal.SIGTERM, signal_handler, signal.SIGTERM, None)
            log.debug("Signal handlers registered for SIGINT and SIGTERM.")
        except NotImplementedError:
             log.warning("Signal handlers not supported on this platform (e.g., Windows). Use Ctrl+C carefully.")
        except Exception as e:
             log.error(f"Error setting signal handlers: {e}")

        try:
            asyncio.run(main_server())
        except KeyboardInterrupt:
             # This might happen if signal handler setup failed or during startup
             log.info("KeyboardInterrupt received directly. Attempting shutdown...")
             # Manually trigger shutdown process if stop_event wasn't set
             if not stop_event.is_set():
                  stop_event.set()
                  if akita_server_instance: akita_server_instance.shutdown()
                  # We can't easily await async tasks here, rely on finally block
        except Exception as e:
             log.critical(f"Unhandled exception in server mode: {e}", exc_info=True)
             sys.exit(1)
        finally:
             # --- Final Cleanup for Server Mode ---
             log.info("Performing final server cleanup...")
             # Ensure Reticulum is stopped in server mode on exit
             if reticulum_instance and hasattr(reticulum_instance, 'stop'):
                  log.info("Stopping Reticulum instance...")
                  try:
                       reticulum_instance.stop()
                       log.info("Reticulum stopped.")
                  except Exception as e:
                       log.error(f"Error during final Reticulum stop: {e}")
             log.info("Server shutdown sequence complete.")

    elif args.mode == 'cli':
         # Run CLI in the main thread (it handles its own Reticulum start/stop)
         main_cli() # Note: main_cli now calls sys.exit() internally
    else:
         # Should not happen with choices defined, but handle anyway
         main_parser.print_help()


if __name__ == "__main__":
    main()
