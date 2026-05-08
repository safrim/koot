import os
import pytest
from koot.identity.derivation.pipeline import EntropyPipeline

@pytest.fixture
def core_master_key():
    return os.urandom(32)

@pytest.fixture
def pipeline():
    return EntropyPipeline()

def test_tenant_key_generation(pipeline):
    tenant_key = pipeline.generate_tenant_master_key()
    assert len(tenant_key) == 32
    assert isinstance(tenant_key, bytes)

def test_wrap_and_unwrap_escrow(pipeline, core_master_key):
    # Generate a random tenant key
    original_tenant_key = pipeline.generate_tenant_master_key()
    
    # Wrap it for escrow
    escrowed_hex = pipeline.wrap_for_escrow(original_tenant_key, core_master_key)
    
    # Ensure it's a string and longer than the original key (due to nonce and auth tag)
    assert isinstance(escrowed_hex, str)
    assert len(bytes.fromhex(escrowed_hex)) > 32
    
    # Unwrap it
    recovered_tenant_key = pipeline.unwrap_from_escrow(escrowed_hex, core_master_key)
    
    # Verify the recovered key perfectly matches the original
    assert recovered_tenant_key == original_tenant_key

def test_unwrap_with_wrong_master_key(pipeline, core_master_key):
    original_tenant_key = pipeline.generate_tenant_master_key()
    escrowed_hex = pipeline.wrap_for_escrow(original_tenant_key, core_master_key)
    
    wrong_master_key = os.urandom(32)
    
    # Attempting to unwrap with the wrong key must fail
    with pytest.raises(ValueError, match="Escrow decryption failed"):
        pipeline.unwrap_from_escrow(escrowed_hex, wrong_master_key)

def test_unwrap_tampered_payload(pipeline, core_master_key):
    original_tenant_key = pipeline.generate_tenant_master_key()
    escrowed_hex = pipeline.wrap_for_escrow(original_tenant_key, core_master_key)
    
    # Tamper with the hex string (flip a character)
    tampered_hex = escrowed_hex[:-1] + ('a' if escrowed_hex[-1] != 'a' else 'b')
    
    with pytest.raises(ValueError, match="Escrow decryption failed"):
        pipeline.unwrap_from_escrow(tampered_hex, core_master_key)