import pytest
import time
import os
import json
from typing import Optional
from koot.core.envelope.envelope import EnvelopeHeader, SecretEnvelope
from koot.plugins.ghost import GhostPlugin
from koot.storage.adapters.base import StorageDriver

class MockStorageDriver(StorageDriver):
    """A mock storage driver to verify write/delete behavior during testing."""
    def __init__(self):
        self.store = {}
        self.wipe_history = []

    def write(self, key: str, data: bytes) -> bool:
        # Track if a wipe of zeros was applied to a key
        if key in self.store and all(b == 0 for b in data):
            self.wipe_history.append(key)
        self.store[key] = data
        return True

    def read(self, key: str) -> Optional[bytes]:
        return self.store.get(key)

    def delete(self, key: str) -> bool:
        if key in self.store:
            del self.store[key]
            return True
        return False

    def exists(self, key: str) -> bool:
        return key in self.store


def test_ghost_plugin_hmac_enforcement_and_ttl():
    storage = MockStorageDriver()
    
    # Generate a mock 256-bit vault MAC key for the session
    vault_mac_key = os.urandom(32) 
    ghost = GhostPlugin(storage, vault_mac_key)
    
    # ==========================================
    # PART 1: Standard TTL Evaluation Logic
    # ==========================================
    
    # 1. Create a persistent envelope (No TTL)
    header_persistent = EnvelopeHeader(
        version="1.0", content_type="password", crypto_suite_id="aes-gcm", 
        iv="iv1==", merkle_root="root1=="
    )
    env_persistent = SecretEnvelope(header_persistent, b"persistent_secret_data")
    storage.write("key_persistent", env_persistent.serialize(vault_mac_key))
    
    # 2. Create an expired envelope (TTL in the past)
    header_expired = EnvelopeHeader(
        version="1.0", content_type="note", crypto_suite_id="aes-gcm", 
        iv="iv2==", merkle_root="root2==", expires_at=time.time() - 3600 # 1 hour ago
    )
    env_expired = SecretEnvelope(header_expired, b"expired_secret_data")
    storage.write("key_expired", env_expired.serialize(vault_mac_key))
    
    # 3. Create an active envelope (TTL in the future)
    header_active = EnvelopeHeader(
        version="1.0", content_type="note", crypto_suite_id="aes-gcm", 
        iv="iv3==", merkle_root="root3==", expires_at=time.time() + 3600 # 1 hour ahead
    )
    env_active = SecretEnvelope(header_active, b"active_secret_data")
    storage.write("key_active", env_active.serialize(vault_mac_key))
    
    # Scan legitimate keys
    keys_to_scan = ["key_persistent", "key_expired", "key_active"]
    purged = ghost.scan_and_purge(keys_to_scan)
    
    # Assertions for standard logic
    assert purged == 1, "Only one envelope should have been purged"
    assert storage.exists("key_persistent") is True, "Persistent envelope should remain"
    assert storage.exists("key_active") is True, "Active envelope should remain"
    assert storage.exists("key_expired") is False, "Expired envelope should be deleted"
    assert "key_expired" in storage.wipe_history, "Expired data was not securely zeroed"

    # ==========================================
    # PART 2: Confused Deputy Tampering Attack
    # ==========================================
    
    # Create a highly sensitive target envelope meant to last a long time
    header_target = EnvelopeHeader(
        version="1.0", content_type="key", crypto_suite_id="aes-gcm", 
        iv="iv_target==", merkle_root="root_target==", expires_at=time.time() + 86400 # 1 day ahead
    )
    env_target = SecretEnvelope(header_target, b"highly_sensitive_data")
    legitimate_data = env_target.serialize(vault_mac_key)
    
    # THE ATTACK: Adversary intercepts the JSON and changes the TTL to the past
    parsed_attack = json.loads(legitimate_data.decode('utf-8'))
    parsed_attack["header"]["expires_at"] = time.time() - 86400 # Change to yesterday
    
    # Write the tampered data back to storage (simulating file system manipulation)
    tampered_data = json.dumps(parsed_attack).encode('utf-8')
    storage.write("key_tampered", tampered_data)

    # Run the GhostPlugin scan on the tampered key
    purged_tampered = ghost.scan_and_purge(["key_tampered"])

    # Assertions for security countermeasures
    assert purged_tampered == 0, "CRITICAL FAILURE: Plugin fell for Confused Deputy attack!"
    assert storage.exists("key_tampered") is True, "Tampered envelope was illegally deleted."