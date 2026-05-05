import json
import hashlib
import os
import time
from pathlib import Path
from typing import Optional, Dict, Any

class AuditLogger:
    """
    An immutable, append-only audit logger with cryptographic log rotation (sealing).
    Ensures that every access or system action is recorded and chained to the previous log.
    """
    def __init__(self, log_dir: str = "vault_logs", max_size_bytes: int = 50 * 1024 * 1024):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.max_size = max_size_bytes
        self.current_log_path = self.log_dir / "audit.log"
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
        with open(self.current_log_path, "w") as f:
            f.write(json.dumps(init_entry) + "\n")

    def log(self, action: str, actor: str, details: Optional[Dict[str, Any]] = None):
        """Appends a new entry to the audit log."""
        # Check if rotation is needed before writing
        if self.current_log_path.exists() and self.current_log_path.stat().st_size >= self.max_size:
            self.rotate()

        entry = {
            "timestamp": time.time(),
            "action": action,
            "actor": actor,
            "details": details or {}
        }
        
        with open(self.current_log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    def rotate(self):
        """
        Seals the current log by computing its SHA-256 hash, 
        renaming it, and starting a new log epoch.
        """
        if not self.current_log_path.exists():
            return

        # 1. Calculate hash of the current log file
        hasher = hashlib.sha256()
        with open(self.current_log_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        final_hash = hasher.hexdigest()

        # 2. Rename (Seal) the current log
        timestamp = int(time.time())
        sealed_name = f"audit_{timestamp}.sealed"
        sealed_path = self.log_dir / sealed_name
        os.rename(self.current_log_path, sealed_path)

        # 3. Start new log with the cryptographic link
        self._start_new_epoch(prev_hash=final_hash)