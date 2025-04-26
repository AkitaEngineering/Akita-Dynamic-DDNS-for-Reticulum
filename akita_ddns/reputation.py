# akita_ddns/reputation.py
import logging
import threading
from typing import Dict, Any

from .storage import PersistentStorage

# Use logger specific to this module
log = logging.getLogger(__name__)

class ReputationManager:
    """Manages reputation scores for nodes, with persistence."""

    def __init__(self, storage_handler: PersistentStorage, config: Dict[str, Any]):
        self.storage = storage_handler
        self.config = config
        # {node_identity_hash_hex: score_int}
        self._reputation: Dict[str, int] = {}
        self._lock = threading.RLock() # Protects access to _reputation
        self._load_initial_state() # Load state during initialization

    def _load_initial_state(self):
         """Loads the reputation scores from the persistent storage."""
         with self._lock:
              self._reputation = self.storage.load_reputation()
              log.info(f"Initial reputation scores loaded for {len(self._reputation)} nodes.")

    def update_reputation(self, node_hash: bytes, score_change: int):
        """
        Updates the reputation score for a given node and persists the change.

        Args:
            node_hash: The identity hash of the node.
            score_change: The amount to add to the node's score (can be negative).
        """
        # Input validation
        if not isinstance(node_hash, bytes):
            log.warning("Invalid node_hash type provided for reputation update.")
            return
        if not isinstance(score_change, int):
             log.warning(f"Invalid score_change type ({type(score_change)}) for reputation update of {node_hash.hex()}.")
             return

        node_hash_hex = node_hash.hex()
        with self._lock:
            current_score = self._reputation.get(node_hash_hex, 0)
            new_score = current_score + score_change
            # Optional: Add bounds to reputation scores (e.g., min/max values)
            # new_score = max(-100, min(100, new_score)) # Example bounds
            self._reputation[node_hash_hex] = new_score
            log.debug(f"Updated reputation for {node_hash_hex}: {new_score} (Change: {score_change:+})")
            # Persist the change immediately
            self.storage.save_reputation(self._reputation) # Pass internal dict

    def get_reputation(self, node_hash: bytes) -> int:
        """Gets the current reputation score for a node, defaulting to 0 if unknown."""
        if not isinstance(node_hash, bytes):
             log.warning("Invalid node_hash type provided for get_reputation.")
             return 0 # Return default score for invalid input

        node_hash_hex = node_hash.hex()
        with self._lock:
            return self._reputation.get(node_hash_hex, 0)

    def get_all_reputations(self) -> Dict[str, int]:
        """Returns a copy of all current reputation scores."""
        with self._lock:
            return self._reputation.copy()

