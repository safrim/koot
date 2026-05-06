import os
import time
import json
import hmac
import hashlib
import logging
from typing import List
from koot.storage.adapters.base import StorageDriver

logger = logging.getLogger(__name__)

class GhostPlugin:
    """
    Time-To-Live (TTL) & Ephemeral Secrets (The "Ghost" Plugin).
    Periodically scans Envelopes and cryptographically wipes expired secrets,
    strictly enforcing HMAC Authenticated Metadata to prevent Confused Deputy attacks.
    """
    def __init__(self, storage_adapter: StorageDriver, vault_mac_key: bytes):
        self.storage = storage_adapter
        self.vault_mac_key = vault_mac_key 

    def scan_and_purge(self, keys: List[str]) -> int:
        """
        Scans the provided envelope keys. Verifies HMAC signatures.
        If an envelope's TTL has legitimately expired, it wipes the data.
        """
        purged_count = 0
        for key in keys:
            raw_data = self.storage.read(key)
            if not raw_data:
                continue
            
            try:
                parsed = json.loads(raw_data.decode('utf-8'))
                header_dict = parsed.get("header", {})
                provided_mac = parsed.get("header_mac", "")
                
                # 1. Reconstruct the exact header bytes (must be sorted exactly as serialized)
                header_json_bytes = json.dumps(header_dict, sort_keys=True).encode('utf-8')
                
                # 2. Calculate what the MAC *should* be
                expected_mac = hmac.new(self.vault_mac_key, header_json_bytes, hashlib.sha256).hexdigest()
                
                # 3. Cryptographic Constant-Time Comparison
                if not hmac.compare_digest(expected_mac, provided_mac):
                    logger.critical(f"SECURITY ALERT: Envelope {key} metadata was tampered with! Skipping wipe.")
                    continue # ABORT: Do not trust the TTL, do not wipe!
                    
                # 4. If MAC matches, it is statistically impossible it was tampered with. Safe to check TTL.
                expires_at = header_dict.get("expires_at")
                
                if expires_at is not None and time.time() >= expires_at:
                    logger.info(f"GhostPlugin: Envelope {key} legally expired. Initiating wipe...")
                    self._cryptographic_wipe(key, len(raw_data))
                    purged_count += 1
                    
            except Exception as e:
                logger.error(f"GhostPlugin: Malformed or unreadable envelope {key}: {e}")
                continue
                    
        return purged_count

    def _cryptographic_wipe(self, key: str, size: int):
        """
        Overwrites the storage location with cryptographically secure random bytes
        and then zeros before unlinking/deleting to prevent data recovery.
        """
        # 1. Overwrite with CSPRNG data
        secure_wipe_data = os.urandom(size)
        self.storage.write(key, secure_wipe_data)
        
        # 2. Overwrite with zeros
        zero_wipe_data = b'\x00' * size
        self.storage.write(key, zero_wipe_data)
        
        # 3. Unlink/delete the record
        self.storage.delete(key)
        logger.info(f"GhostPlugin: Cryptographically wiped and deleted {key} successfully.")