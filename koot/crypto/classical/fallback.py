import os
import ctypes
import sys

VENDORED_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vendored"))
LIB_EXT = ".dylib" if sys.platform == "darwin" else ".so"
LIBAES_PATH = os.path.join(VENDORED_DIR, f"libaesgcm{LIB_EXT}")

if not os.path.exists(LIBAES_PATH):
    raise RuntimeError("CRITICAL: Vendored libaesgcm not found. Run scripts/build_vendored_crypto.py")

_libaes = ctypes.CDLL(LIBAES_PATH)

class SoftwareAESGCM:
    """
    Standard software fallback for AES-256-GCM.
    Operates strictly through the locally vendored C implementation.
    """
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ct_buffer = ctypes.create_string_buffer(len(plaintext) + 16) # Ciphertext + Tag
        
        # Hypothetical C-binding invocation
        _libaes.encrypt_aes_gcm(key, plaintext, len(plaintext), ct_buffer)
        
        return bytes(ct_buffer), nonce

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        pt_buffer = ctypes.create_string_buffer(len(ciphertext) - 16)
        
        # Hypothetical C-binding invocation
        res = _libaes.decrypt_aes_gcm(key, ciphertext, len(ciphertext), pt_buffer)
        if res != 1:
            raise ValueError("AES-GCM Decryption failed: Invalid MAC tag or corrupted data.")
            
        return bytes(pt_buffer)