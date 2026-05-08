import threading
import secrets
import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)

class OverrideMatrix:
    """
    High-priority command interface for manual system overrides.
    Requires both the Admin Token AND the Master Certificate Hash
    to execute critical halts or aborts. Sub-user contexts are silently ignored.
    """
    def __init__(self, admin_token: str, master_cert_hash: str):
        self._admin_token = admin_token
        self._master_cert_hash = master_cert_hash
        self._is_halted = False
        self._lock = threading.Lock() 
        self._abort_callbacks: list[Callable] = []

    def verify_master_authority(self, token: str, client_cert_hash: str) -> bool:
        """Strictly validates both the token and the certificate hash."""
        # Use compare_digest for both to mitigate timing attacks
        valid_token = secrets.compare_digest(self._admin_token, token)
        valid_cert = secrets.compare_digest(self._master_cert_hash, client_cert_hash)
        
        return valid_token and valid_cert

    def trigger_global_halt(self, token: str, client_cert_hash: str) -> bool:
        """Instantly sets the system to a halted state."""
        if not self.verify_master_authority(token, client_cert_hash):
            # Silently drop unauthorized requests to mask defensive behavior
            logger.warning("Unauthorized override attempt. Silently dropping.")
            return False
        
        with self._lock:
            self._is_halted = True
            logger.critical("MANUAL OVERRIDE: Global system halt engaged.")
            return True

    def register_abort_callback(self, callback: Callable):
        """Register functions to call when a manual abort is triggered."""
        self._abort_callbacks.append(callback)

    def trigger_abort_all(self, token: str, client_cert_hash: str) -> bool:
        """Executes all registered abort sequences (e.g., stopping a Nuke)."""
        if not self.verify_master_authority(token, client_cert_hash):
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
        with self._lock: 
            return self._is_halted

    def reset_halt(self, token: str, client_cert_hash: str) -> bool:
        """Resets the halt state."""
        if self.verify_master_authority(token, client_cert_hash):
            with self._lock: 
                self._is_halted = False
            return True
        return False