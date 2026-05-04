# koot/crypto/classical/accelerated.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class HardwareAESGCM:
    """
    Hardware-accelerated AES-256-GCM.
    Loaded when the EnvironmentSensor detects AES-NI or similar CPU instruction sets.
    (Note: In Python, the underlying OpenSSL layer usually handles AES-NI automatically,
    but separating this driver allows us to swap in native C-extensions or specialized
    hardware libraries in the future without changing the fallback).
    """
    
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return ciphertext, nonce

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)