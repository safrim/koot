import threading
import secrets
import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)

class OverrideMatrix:
    """
    High-priority command interface for manual system overrides.
    Requires an Admin Token to execute critical halts or aborts.
    """
    def __init__(self, admin_token: str):
        self._admin_token = admin_token
        self._is_halted = False
        self._lock = threading.Lock() # Defined here with underscore
        self._abort_callbacks: list[Callable] = []

    def verify_token(self, token: str) -> bool:
        return secrets.compare_digest(self._admin_token, token)

    def trigger_global_halt(self, token: str) -> bool:
        """Instantly sets the system to a halted state."""
        if not self.verify_token(token):
            logger.warning("Unauthorized attempt to trigger global halt!")
            return False
        
        # FIX: Changed self.lock to self._lock to match __init__
        with self._lock:
            self._is_halted = True
            logger.critical("MANUAL OVERRIDE: Global system halt engaged.")
            return True

    def register_abort_callback(self, callback: Callable):
        """Register functions to call when a manual abort is triggered."""
        self._abort_callbacks.append(callback)

    def trigger_abort_all(self, token: str) -> bool:
        """Executes all registered abort sequences (e.g., stopping a Nuke)."""
        if not self.verify_token(token):
            return False
            
        logger.info("MANUAL OVERRIDE: Executing all registered abort sequences.")
        for callback in self._abort_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Abort callback failed: {e}")
        return True

    @property
    def is_halted(self) -> bool:
        with self._lock: # Ensure underscore is used here as well
            return self._is_halted

    def reset_halt(self, token: str) -> bool:
        """Resets the halt state."""
        if self.verify_token(token):
            with self._lock: # Added lock protection for the reset
                self._is_halted = False
            return True
        return False