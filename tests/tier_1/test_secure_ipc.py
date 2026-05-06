import os
import time
import multiprocessing
import pytest
from koot.core.bus.registry import SecurePipeConnection, AdaptiveRegistry

class DummyCryptoPlugin:
    """A mock plugin specifically formatted for AdaptiveRegistry's action/kwargs contract."""
    @staticmethod
    def process_data(data: str):
        return f"Processed: {data}"

def test_secure_pipe_encryption_verification():
    """
    Directly inspects the raw pipe to prove plaintext secrets 
    are NOT traversing the OS layer.
    """
    key = os.urandom(32)
    parent_conn, child_conn = multiprocessing.Pipe()
    secure_parent = SecurePipeConnection(parent_conn, key)

    secret_message = "HIGHLY_CLASSIFIED_ROOT_KEY"
    secure_parent.send({"secret": secret_message})

    # Intercept the raw data directly from the un-wrapped child connection
    raw_intercept = child_conn.recv()
    
    # Assert the structure is (nonce, ciphertext)
    assert len(raw_intercept) == 2
    nonce, ciphertext = raw_intercept
    
    # Prove the plaintext is nowhere in the byte stream
    assert secret_message.encode() not in ciphertext
    assert len(nonce) == 12

def test_adaptive_registry_secure_lifecycle():
    """
    Tests the end-to-end mounting, dispatching, and shutdown of a plugin
    using the volatile ChaCha20-Poly1305 key exchange within the real registry.
    """
    registry = AdaptiveRegistry(override_matrix={"ignore_thermals": True})
    
    # 1. Mount
    registry.mount_plugin("crypto_dummy", DummyCryptoPlugin)
    assert "crypto_dummy" in registry.plugins
    assert registry.plugins["crypto_dummy"]["process"].is_alive()

    # 2. Secure Dispatch
    # AdaptiveRegistry dispatch signature: dispatch(plugin_name, action, **kwargs)
    response_data = registry.dispatch("crypto_dummy", action="process_data", data="test_string")
    
    # AdaptiveRegistry un-nests the response and just returns the data
    assert response_data == "Processed: test_string"

    # 3. Graceful Shutdown
    registry.shutdown_all()
    time.sleep(0.1) # Brief pause to allow OS to terminate the isolated process
    assert not registry.plugins["crypto_dummy"]["process"].is_alive()