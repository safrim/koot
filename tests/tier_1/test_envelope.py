import base64
from koot.core.envelope.envelope import EnvelopeHeader, SecretEnvelope

def test_secret_envelope():
    print("[*] Initializing Phase 1.1 Test: Secret Envelope")

    # 1. Create a dummy header (mocking the crypto layer for now)
    dummy_header = EnvelopeHeader(
        version="1.0",
        content_type="credential/password",
        crypto_suite_id="AES-256-GCM_ML-KEM",
        iv=base64.b64encode(b"dummy_nonce_1234").decode('utf-8'),
        merkle_root=base64.b64encode(b"dummy_merkle_root_hash").decode('utf-8')
    )

    # 2. Mock some encrypted raw bytes
    dummy_encrypted_payload = b"\x8c\x1a\x9b\x0f\x42\x7d\x11"

    # 3. Pack the Envelope
    envelope = SecretEnvelope(header=dummy_header, payload=dummy_encrypted_payload)
    serialized_data = envelope.serialize()
    
    print(f"\n[+] Serialized Output (Bytes):\n{serialized_data}")

    # 4. Unpack the Envelope
    restored_envelope = SecretEnvelope.deserialize(serialized_data)
    
    print(f"\n[+] Deserialized Object: {restored_envelope}")
    assert restored_envelope.payload == dummy_encrypted_payload, "Payload mismatch!"
    assert restored_envelope.header.crypto_suite_id == "AES-256-GCM_ML-KEM", "Header mismatch!"
    
    print("\n[SUCCESS] Envelope serialization and deserialization completed flawlessly.")

if __name__ == "__main__":
    test_secret_envelope()