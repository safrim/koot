import ctypes
import os
import sys

# Dynamically locate the localized, vendored library
VENDORED_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "vendored"))
LIB_EXT = ".dylib" if sys.platform == "darwin" else ".so"
LIBOQS_PATH = os.path.join(VENDORED_DIR, f"liboqs{LIB_EXT}")

if not os.path.exists(LIBOQS_PATH):
    raise RuntimeError(f"CRITICAL: Vendored liboqs not found at {LIBOQS_PATH}. Run scripts/build_vendored_crypto.py")

# Load the library in memory
_liboqs = ctypes.CDLL(LIBOQS_PATH)

class KyberKEM:
    """
    Post-Quantum Key Encapsulation Mechanism using ML-KEM (Kyber).
    Now completely decoupled from PyPI. Runs strictly via vendored C-library.
    """
    ALGORITHM = "Kyber768"
    PUBLIC_KEY_LEN = 1184
    SECRET_KEY_LEN = 2400
    SHARED_SECRET_LEN = 32
    CIPHERTEXT_LEN = 1088

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        public_key = ctypes.create_string_buffer(KyberKEM.PUBLIC_KEY_LEN)
        secret_key = ctypes.create_string_buffer(KyberKEM.SECRET_KEY_LEN)
        
        # Invoke the C API directly
        result = _liboqs.OQS_KEM_kyber_768_keypair(public_key, secret_key)
        if result != 0:
            raise Exception("Vendored Kyber keypair generation failed.")
            
        return bytes(public_key), bytes(secret_key)

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        ciphertext = ctypes.create_string_buffer(KyberKEM.CIPHERTEXT_LEN)
        shared_secret = ctypes.create_string_buffer(KyberKEM.SHARED_SECRET_LEN)
        
        result = _liboqs.OQS_KEM_kyber_768_encaps(ciphertext, shared_secret, public_key)
        if result != 0:
            raise Exception("Vendored Kyber encapsulation failed.")
            
        return bytes(ciphertext), bytes(shared_secret)

    @staticmethod
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        shared_secret = ctypes.create_string_buffer(KyberKEM.SHARED_SECRET_LEN)
        
        # Ensures memory buffers are strictly managed directly via C-types
        result = _liboqs.OQS_KEM_kyber_768_decaps(shared_secret, ciphertext, secret_key)
        if result != 0:
            raise Exception("Vendored Kyber decapsulation failed.")
            
        return bytes(shared_secret)