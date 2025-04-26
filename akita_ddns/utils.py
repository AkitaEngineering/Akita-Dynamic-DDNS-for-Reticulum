# akita_ddns/utils.py
import time
import threading
from collections import deque
import logging
import re # For potential future validation
from typing import Deque, Optional, Tuple

# Use logger specific to this module
log = logging.getLogger(__name__)

class RateLimiter:
    """
    Simple token-bucket-like rate limiter.
    Refills tokens based on elapsed time. Thread-safe.
    """

    def __init__(self, rate: float, capacity: Optional[float] = None):
        """
        Initializes the rate limiter.

        Args:
            rate: Requests allowed per second (token refill rate).
            capacity: Maximum burst capacity (max tokens). Defaults to rate.
        """
        if rate <= 0:
            raise ValueError("Rate must be positive")
        self.rate = float(rate)
        # Ensure capacity is at least the rate
        self.capacity = max(self.rate, float(capacity)) if capacity is not None else self.rate
        self.tokens = self.capacity # Start with a full bucket
        self.last_update = time.monotonic() # Use monotonic clock for intervals
        self._lock = threading.Lock()
        log.info(f"RateLimiter initialized: rate={self.rate}/s, capacity={self.capacity}")

    def check(self) -> bool:
        """
        Checks if a request is allowed based on the current rate limit.
        Consumes one token if allowed.

        Returns:
            True if the request is allowed, False otherwise.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Add new tokens based on elapsed time, up to capacity
            self.tokens += elapsed * self.rate
            self.tokens = min(self.tokens, self.capacity)

            # Check if enough tokens are available (at least 1.0)
            if self.tokens >= 1.0:
                self.tokens -= 1.0
                # Log remaining tokens only periodically or in debug to avoid log spam
                # log.debug(f"Rate limit check passed. Tokens remaining: {self.tokens:.2f}")
                return True
            else:
                # Log rate limit exceeded event clearly
                log.warning(f"Rate limit exceeded. Tokens needed: 1.0, Available: {self.tokens:.2f}")
                return False

def parse_name(full_name: str, default_namespace: str) -> Tuple[str, str]:
    """
    Parses a potentially qualified name into (name, namespace).
    Strips whitespace and performs basic validation.

    Args:
        full_name: The name string (e.g., "myhost", "myhost.mynamespace").
        default_namespace: The namespace to use if none is specified in full_name.

    Returns:
        A tuple containing (name, namespace).

    Raises:
        ValueError: If the name format is invalid (e.g., empty parts, invalid characters).
    """
    if not isinstance(full_name, str) or not full_name.strip():
        raise ValueError("Name cannot be empty or just whitespace.")
    if not isinstance(default_namespace, str) or not default_namespace.strip():
         # This indicates a configuration issue if the default is invalid
         log.error("Invalid default_namespace provided to parse_name.")
         raise ValueError("Internal configuration error: Invalid default namespace.")


    # Strip leading/trailing whitespace from the full name
    full_name = full_name.strip()

    parts = full_name.split('.', 1)
    name_part = parts[0].strip()
    # Use default namespace if no '.' was found OR if the part after '.' is empty/whitespace
    namespace_part = parts[1].strip() if len(parts) > 1 and parts[1].strip() else default_namespace.strip()

    # Validate parts are not empty after stripping
    if not name_part:
         raise ValueError("Name part cannot be empty.")
    if not namespace_part:
         # If the default namespace was somehow empty or whitespace
         raise ValueError("Namespace part cannot be empty (check default namespace).")

    # --- Optional: Add more validation for allowed characters ---
    # Example: Allow typical hostname characters in name_part
    # if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", name_part):
    #      raise ValueError(f"Invalid characters in name part: '{name_part}'")
    # Example: Allow simple alphanumeric/hyphen/underscore in namespace_part
    # if not re.match(r"^[a-zA-Z0-9_-]+$", namespace_part):
    #      raise ValueError(f"Invalid characters in namespace part: '{namespace_part}'")
    # Keep it simple for now, allowing most non-empty strings without '.' in namespace.

    log.debug(f"Parsed '{full_name}' -> name='{name_part}', namespace='{namespace_part}'")
    return name_part, namespace_part

