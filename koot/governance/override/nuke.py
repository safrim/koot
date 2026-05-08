import threading
import time
import shutil
import logging
from pathlib import Path
from typing import Callable, Optional
from koot.governance.override.interlock import OverrideMatrix

class NukeProtocol:
    """
    Implementation of the 'Dead Man's Switch' and system-wide 'Nuke' protocol.
    Strictly enforces Master Authority for arming, disarming, and heartbeats.
    """
    def __init__(
        self, 
        override_matrix: OverrideMatrix,
        target_path: Optional[str] = None, 
        emergency_callback: Optional[Callable] = None
    ):
        self.matrix = override_matrix
        self.target_path = Path(target_path) if target_path else None
        self.emergency_callback = emergency_callback
        self.timeout = 0
        self.last_heartbeat = 0
        self.is_armed = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("NukeProtocol")

    def arm(self, timeout_seconds: int, token: str, client_cert_hash: str) -> bool:
        """Arms the Dead Man's Switch with a specific timeout."""
        if not self.matrix.verify_master_authority(token, client_cert_hash):
            self.logger.warning("Unauthorized attempt to ARM Nuke Protocol. Dropping.")
            return False

        self.timeout = timeout_seconds
        self.last_heartbeat = time.time()
        self.is_armed = True
        self._stop_event.clear()
        
        if not self._monitor_thread or not self._monitor_thread.is_alive():
            self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._monitor_thread.start()
        
        self.logger.info(f"Nuke Protocol ARMED. Timeout: {timeout_seconds}s")
        return True

    def heartbeat(self, token: str, client_cert_hash: str) -> bool:
        """Resets the timer, preventing the Nuke from triggering."""
        if not self.matrix.verify_master_authority(token, client_cert_hash):
            self.logger.warning("Unauthorized Nuke heartbeat attempt. Dropping.")
            return False

        if self.is_armed:
            self.last_heartbeat = time.time()
            return True
        return False

    def disarm(self, token: str, client_cert_hash: str) -> bool:
        """Safely deactivates the protocol."""
        if not self.matrix.verify_master_authority(token, client_cert_hash):
            self.logger.warning("Unauthorized attempt to DISARM Nuke Protocol. Dropping.")
            return False

        self.is_armed = False
        self._stop_event.set()
        self.logger.info("Nuke Protocol DISARMED.")
        return True

    def _monitor_loop(self):
        """Background loop to check if the timeout has expired."""
        while not self._stop_event.is_set():
            if not self.is_armed:
                break
            
            # If the manual override interlock is engaged, stop the monitor immediately
            if self.matrix.is_halted:
                self.logger.info("Nuke Protocol HALTED by Manual Override Interlock.")
                self.is_armed = False
                break
                
            elapsed = time.time() - self.last_heartbeat
            if elapsed >= self.timeout:
                self._execute_nuke()
                break
            
            time.sleep(0.5)

    def _execute_nuke(self):
        """The emergency execution logic."""
        self.is_armed = False
        self.logger.critical("!!! DEAD MAN'S SWITCH TRIGGERED !!!")
        
        if self.emergency_callback:
            try:
                self.emergency_callback()
            except Exception as e:
                self.logger.error(f"Error in emergency callback: {e}")

        if self.target_path and self.target_path.exists():
            try:
                if self.target_path.is_dir():
                    shutil.rmtree(self.target_path)
                else:
                    self.target_path.unlink()
                self.logger.critical(f"Target path {self.target_path} has been WIPED.")
            except Exception as e:
                self.logger.error(f"Failed to wipe target: {e}")

    def trigger_now(self, token: str, client_cert_hash: str) -> bool:
        """Manual override to trigger the nuke immediately."""
        if not self.matrix.verify_master_authority(token, client_cert_hash):
            self.logger.warning("Unauthorized attempt to trigger Nuke. Silently dropping.")
            return False
            
        self._execute_nuke()
        return True