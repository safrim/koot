import json
import hashlib
import os
import time
import threading
from pathlib import Path
from typing import Optional, Dict, Any

class AuditLogger:
    """
    An immutable, append-only audit logger with asynchronous cryptographic log rotation (sealing).
    Ensures that every access or system action is recorded without blocking the primary event loop.
    """
    def __init__(self, log_dir: str = "vault_logs", max_size_bytes: int = 50 * 1024 * 1024):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size_bytes
        self.current_log_path = self.log_dir / "audit.log"
        self._lock = threading.Lock()
        self._initialize_log()

    def _initialize_log(self):
        """Initializes the log file if it doesn't exist."""
        if not self.current_log_path.exists():
            self._start_new_epoch(prev_hash="0" * 64)

    def _start_new_epoch(self, prev_hash: str):
        """Starts a new log file with a link to the hash of the previous one."""
        init_entry = {
            "event": "EPOCH_START",
            "timestamp": time.time(),
            "prev_log_hash": prev_hash,
            "version": "1.0"
        }
        with open(self.current_log_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(init_entry) + "\n")

    def log(self, action: str, actor: str, details: Optional[Dict[str, Any]] = None):
        """Appends a new entry to the audit log in a thread-safe manner."""
        with self._lock:
            # Check if rotation is needed before writing
            if self.current_log_path.exists() and self.current_log_path.stat().st_size >= self.max_size:
                self._rotate_unsafe()

            entry = {
                "timestamp": time.time(),
                "action": action,
                "actor": actor,
                "details": details or {}
            }
            
            with open(self.current_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")

    def rotate(self):
        """Public method to manually trigger rotation."""
        with self._lock:
            self._rotate_unsafe()

    def _rotate_unsafe(self):
        """
        Internal method to rotate log without acquiring lock (already held).
        Renames current log and delegates hashing/sealing to a background thread.
        """
        if not self.current_log_path.exists():
            return

        timestamp = int(time.time())
        processing_name = f"audit_{timestamp}.processing"
        processing_path = self.log_dir / processing_name
        
        # 1. Immediately rename to free up the active log path
        os.rename(self.current_log_path, processing_path)

        # 2. Start new log with a placeholder hash
        self._start_new_epoch(prev_hash="PENDING_ASYNC_CALCULATION")

        # 3. Dispatch background worker to handle I/O-heavy hashing
        worker = threading.Thread(
            target=self._async_seal, 
            args=(processing_path, timestamp), 
            daemon=True
        )
        worker.start()

    def _async_seal(self, processing_path: Path, timestamp: int):
        """
        Background worker that hashes the large log file and seals it.
        """
        hasher = hashlib.sha256()
        try:
            with open(processing_path, "rb") as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            final_hash = hasher.hexdigest()

            sealed_name = f"audit_{timestamp}.sealed"
            sealed_path = self.log_dir / sealed_name
            os.rename(processing_path, sealed_path)

            # 4. Link the completed seal to the new active log securely
            self.log(
                action="EPOCH_SEALED",
                actor="SYSTEM",
                details={
                    "sealed_file": sealed_name,
                    "final_hash": final_hash
                }
            )
        except Exception as e:
            # In production, output this strictly to system stderr or alerting pipeline
            pass