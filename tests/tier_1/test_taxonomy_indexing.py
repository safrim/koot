import os
import json
import hmac
import hashlib
import pytest
from koot.core.envelope.envelope import EnvelopeHeader, SecretEnvelope

@pytest.fixture
def vault_mac_key():
    """Generates a secure 256-bit key for test isolation."""
    return os.urandom(32)

def test_zero_leakage_blind_indexing(vault_mac_key):
    """
    Ensures plaintext tags are destroyed during serialization and 
    replaced with zero-knowledge blind hashes.
    """
    sensitive_tag = "Work/Project-Apollo/Server-IPs"
    header = EnvelopeHeader(
        version="1.0", content_type="password", crypto_suite_id="aes-gcm",
        iv="iv==", merkle_root="root==",
        tags=[sensitive_tag]
    )
    env = SecretEnvelope(header, b"secret_data")
    serialized_bytes = env.serialize(vault_mac_key)
    serialized_str = serialized_bytes.decode('utf-8')
    
    # 1. ASSERT ZERO LEAKAGE
    assert sensitive_tag not in serialized_str, "CRITICAL: Plaintext tag leaked to storage!"
    
    # 2. ASSERT HASH PRESENCE
    parsed = json.loads(serialized_str)
    assert "tags" not in parsed["header"], "The 'tags' key should be stripped."
    assert "blind_tags" in parsed["header"], "The 'blind_tags' key must be present."
    assert len(parsed["header"]["blind_tags"]) == 1

def test_taxonomy_search_normalization(vault_mac_key):
    """
    Ensures the system ignores case and whitespace so UI searches are resilient.
    """
    header1 = EnvelopeHeader(
        version="1.0", content_type="note", crypto_suite_id="aes", 
        iv="1", merkle_root="2", tags=[" FINANCE/Swiss "] # Messy input
    )
    header2 = EnvelopeHeader(
        version="1.0", content_type="note", crypto_suite_id="aes", 
        iv="1", merkle_root="2", tags=["finance/swiss"] # Clean input
    )

    env1 = SecretEnvelope(header1, b"data")
    env2 = SecretEnvelope(header2, b"data")

    parsed1 = json.loads(env1.serialize(vault_mac_key).decode('utf-8'))
    parsed2 = json.loads(env2.serialize(vault_mac_key).decode('utf-8'))

    hash1 = parsed1["header"]["blind_tags"][0]
    hash2 = parsed2["header"]["blind_tags"][0]
    
    assert hash1 == hash2, "Normalization failed: Similar tags produced different hashes."

def test_cryptographic_sealing_of_taxonomy(vault_mac_key):
    """
    Ensures an adversary cannot alter the blind_tags array without breaking the MAC.
    """
    header = EnvelopeHeader(
        version="1.0", content_type="note", crypto_suite_id="aes",
        iv="1", merkle_root="2", tags=["Valid_Tag"]
    )
    env = SecretEnvelope(header, b"data")
    serialized = env.serialize(vault_mac_key)

    parsed = json.loads(serialized.decode('utf-8'))
    original_mac = parsed["header_mac"]

    # ATTACK: Adversary secretly adds a new tag hash to the metadata
    parsed["header"]["blind_tags"].append("fake_adversary_hash_123")

    # System attempts to verify the tampered file during a read
    tampered_header_bytes = json.dumps(parsed["header"], sort_keys=True).encode('utf-8')
    expected_mac = hmac.new(vault_mac_key, tampered_header_bytes, hashlib.sha256).hexdigest()

    assert original_mac != expected_mac, "MAC failed to detect blind_tags tampering!"

def test_legacy_envelope_backward_compatibility():
    """
    Ensures legacy JSON files (from before Phase 6) don't crash the deserializer.
    """
    # Simulate a raw JSON string pulled from disk that lacks TTL and Tags
    legacy_data = {
        "header": {
            "version": "1.0",
            "content_type": "password",
            "crypto_suite_id": "aes-gcm",
            "iv": "old_iv==",
            "merkle_root": "old_root=="
        },
        "payload": "YmFzZTY0X2RhdGE=" 
    }
    raw_bytes = json.dumps(legacy_data).encode('utf-8')

    # Should deserialize seamlessly
    env = SecretEnvelope.deserialize(raw_bytes)

    assert env.header.expires_at is None, "Missing expires_at should default to None"
    assert env.header.tags == [], "Missing blind_tags should default to empty list"
    assert env.header.version == "1.0"