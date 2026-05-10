import json
import base64
import hmac
import hashlib
import pytest
from koot.core.envelope.envelope import SecretEnvelope, EnvelopeHeader

def test_secret_envelope_cryptographic_wrapping():
    # 1. Setup mock keys and data
    mock_vault_mac_key = b"super_secret_vault_mac_key_12345"
    mock_payload = b"this_is_a_highly_sensitive_binary_payload"
    
    header = EnvelopeHeader(
        version="1.0.0",
        content_type="credential",
        crypto_suite_id="AES-256-GCM-HKDF",
        iv="mock_iv_string",
        merkle_root="mock_merkle_root_hash",
        tags=["Finance", " Banking ", "TAXES"] # Notice the messy casing/spacing
    )
    
    envelope = SecretEnvelope(header=header, payload=mock_payload)
    
    # 2. Test Serialization & Cryptographic Blinding
    serialized_bytes = envelope.serialize(vault_mac_key=mock_vault_mac_key)
    assert isinstance(serialized_bytes, bytes)
    
    raw_dict = json.loads(serialized_bytes.decode('utf-8'))
    
    # Verify root structural components
    assert "header" in raw_dict
    assert "header_mac" in raw_dict
    assert "payload" in raw_dict
    
    # Verify tags are blinded, normalized, and plaintext is destroyed
    saved_header = raw_dict["header"]
    assert "tags" not in saved_header
    assert "blind_tags" in saved_header
    assert len(saved_header["blind_tags"]) == 3
    
    # Re-calculate the expected hash for "Finance" (which normalizes to "finance")
    expected_finance_hash = hmac.new(mock_vault_mac_key, b"finance", hashlib.sha256).hexdigest()
    expected_taxes_hash = hmac.new(mock_vault_mac_key, b"taxes", hashlib.sha256).hexdigest()
    
    assert expected_finance_hash in saved_header["blind_tags"]
    assert expected_taxes_hash in saved_header["blind_tags"]
    
    # 3. Test Deserialization (Loading back into active memory)
    unwrapped_envelope = SecretEnvelope.deserialize(serialized_bytes)
    
    # Verify Payload Integrity
    assert unwrapped_envelope.payload == mock_payload
    
    # Verify Metadata Integrity
    assert unwrapped_envelope.header.version == "1.0.0"
    assert unwrapped_envelope.header.content_type == "credential"
    assert unwrapped_envelope.header.merkle_root == "mock_merkle_root_hash"
    
    # Verify the blind tags were temporarily loaded into the RAM 'tags' property
    assert expected_finance_hash in unwrapped_envelope.header.tags

def test_deserialize_corrupted_payload_fails():
    # Ensure the system fails gracefully if given garbage data
    corrupted_data = b'{"header": {}, "payload": "not_base64_!@#"}'
    with pytest.raises(ValueError, match="Failed to deserialize Secret Envelope"):
        SecretEnvelope.deserialize(corrupted_data)