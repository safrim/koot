import pytest
from koot.crypto.classical.fallback import SoftwareAESGCM

def test_c_wrapper_rejects_corrupt_data():
    master_key = b"0123456789abcdef0123456789abcdef"
    plaintext = b'{"tenants": {}}'
    
    # Encrypt real data using the C-library
    ciphertext, nonce = SoftwareAESGCM.encrypt(master_key, plaintext)
    
    # Tamper with the encrypted data to force a C-level failure
    corrupt_ciphertext = bytearray(ciphertext)
    corrupt_ciphertext[0] ^= 0xFF
    corrupt_ciphertext = bytes(corrupt_ciphertext)
    
    # The test passes ONLY if your new fix successfully raises the ValueError.
    # If the bug is still there, it returns null bytes, no error is raised, and the test fails.
    with pytest.raises(ValueError):
        SoftwareAESGCM.decrypt(master_key, nonce, corrupt_ciphertext)