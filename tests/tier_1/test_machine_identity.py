import pytest
from koot.identity.machine.tpm_provider import TPMIdentityProvider
from koot.identity.machine.unlock import MachineUnlockManager

def test_tpm_mock_fallback():
    """Verify that the system gracefully falls back to a mock if hardware is missing."""
    provider = TPMIdentityProvider(tcti="mock")
    challenge = b"verify_me"
    sig = provider.create_identity_signature(challenge)
    assert sig.startswith(b"MOCK_TPM_SIG_")

def test_machine_unlock_consistency():
    """Ensure the pipeline is deterministic for the same hardware fingerprint."""
    provider = TPMIdentityProvider()
    manager = MachineUnlockManager(provider)
    
    machine_id = "node-alpha-01"
    nonce = b"fixed_nonce_16bytes"
    
    key1 = manager.generate_vault_key(machine_id, nonce)
    key2 = manager.generate_vault_key(machine_id, nonce)
    
    assert key1 == key2
    assert len(key1) == 32  # Standard AES-256 key length

def test_machine_unlock_uniqueness():
    """Verify that different nonces produce distinct keys."""
    manager = MachineUnlockManager(TPMIdentityProvider())
    
    key1 = manager.generate_vault_key("machine", b"nonce_a_123456789")
    key2 = manager.generate_vault_key("machine", b"nonce_b_123456789")
    
    assert key1 != key2