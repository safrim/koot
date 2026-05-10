import os
import ctypes
from pathlib import Path
import platform

# Locate the compiled shared object
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VENDORED_DIR = PROJECT_ROOT / "koot" / "crypto" / "vendored"

if platform.system() == "Windows":
    lib_path = VENDORED_DIR / "aes_gcm.dll"
else:
    lib_path = VENDORED_DIR / "aes_gcm.so"

if not lib_path.exists():
    raise RuntimeError(f"Vendored crypto library not found at {lib_path}. Run build script.")

_libaes = ctypes.CDLL(str(lib_path))

# Define C function signatures to prevent memory misalignment
# encrypt_aes_gcm(plaintext, len, key, iv, ciphertext_out, tag_out)
_libaes.encrypt_aes_gcm.argtypes = [
    ctypes.c_char_p, ctypes.c_int,  
    ctypes.c_char_p, ctypes.c_char_p, 
    ctypes.c_char_p, ctypes.c_char_p  
]
_libaes.encrypt_aes_gcm.restype = ctypes.c_int

# decrypt_aes_gcm(ciphertext, len, key, iv, tag, plaintext_out)
_libaes.decrypt_aes_gcm.argtypes = [
    ctypes.c_char_p, ctypes.c_int, 
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, 
    ctypes.c_char_p 
]
_libaes.decrypt_aes_gcm.restype = ctypes.c_int

class SoftwareAESGCM:
    """
    Production-grade Python wrapper around the vendored OpenSSL C layer.
    """
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple:
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes for AES-256-GCM")
        
        # Auto-generate a secure 12-byte nonce for this specific operation
        nonce = os.urandom(12)
        
        ciphertext_buffer = ctypes.create_string_buffer(len(plaintext))
        tag_buffer = ctypes.create_string_buffer(16)
        
        res = _libaes.encrypt_aes_gcm(
            plaintext, len(plaintext),
            key, nonce,
            ciphertext_buffer, tag_buffer
        )
        
        if res != 1:
            raise ValueError("AES-GCM Encryption failed.")
        
        # FIX: The ledger expects a tuple of (ciphertext, nonce).
        # We combine the ciphertext and the 16-byte MAC tag together first.
        full_ciphertext = ciphertext_buffer.raw + tag_buffer.raw
        
        return full_ciphertext, nonce

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes")
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short (missing tag)")
        
        # Split the actual ciphertext from the 16-byte authentication tag
        actual_ciphertext = ciphertext[:-16]
        tag = ciphertext[-16:]
        
        pt_buffer = ctypes.create_string_buffer(len(actual_ciphertext))
        
        res = _libaes.decrypt_aes_gcm(
            actual_ciphertext, len(actual_ciphertext),
            key, nonce, tag,
            pt_buffer
        )
        
        if res != 1:
            raise ValueError("AES-GCM Decryption failed: Invalid MAC tag or corrupted data.")
            
        return pt_buffer.raw