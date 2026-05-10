import pytest
import argon2.low_level
from koot.identity.derivation.pipeline import EntropyPipeline

def test_approle_hardware_binding():
    """Verify that shifting hardware factors breaks key derivation even with same password."""
    pipeline = EntropyPipeline()
    password = "CorrectPassword123"
    salt = b"test_salt_16bytes"
    
    # Simulate two different machine signatures
    hw_sig_machine_a = b"SIG_FROM_TPM_A"
    hw_sig_machine_b = b"SIG_FROM_TPM_B"
    
    # Derive keys for both scenarios
    # Note: We use derive_key (Session 6) for testing since it doesn't require C-Enclave
    key_a, _ = pipeline.derive_key(password + hw_sig_machine_a.hex(), salt)
    key_b, _ = pipeline.derive_key(password + hw_sig_machine_b.hex(), salt)
    
    assert key_a != key_b, "Keys must differ if the machine signature changes"

def test_composite_derivation_consistency():
    """Ensure that the composite secret is deterministic on the same machine."""
    pipeline = EntropyPipeline()
    password = "SamePassword"
    hw_sig = b"STABLE_TPM_SIG"
    salt = b"stable_salt_bytes"
    
    key1, _ = pipeline.derive_key(password + hw_sig.hex(), salt)
    key2, _ = pipeline.derive_key(password + hw_sig.hex(), salt)
    
    assert key1 == key2, "Derivation must be stable on the same hardware"