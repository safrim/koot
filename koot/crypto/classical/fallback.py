# koot/crypto/classical/fallback.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SoftwareAESGCM:
    """
    Standard software fallback for AES-256-GCM.
    Used when the EnvironmentSensor determines AES-NI is unavailable.
    """
    
    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None) -> tuple[bytes, bytes]:
        """
        Encrypts the plaintext using AES-256-GCM.
        Returns a tuple of (ciphertext, nonce).
        """
        aesgcm = AESGCM(key)
        # GCM standard nonce size is 12 bytes (96 bits)
        nonce = os.urandom(12)
        
        # The cryptography library's encrypt appends the 16-byte authentication tag 
        # to the end of the ciphertext automatically.
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        return ciphertext, nonce

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes = None) -> bytes:
        """
        Decrypts the ciphertext using AES-256-GCM.
        Validates the authentication tag automatically.
        """
        aesgcm = AESGCM(key)
        # This will raise cryptography.exceptions.InvalidTag if tampered with
        return aesgcm.decrypt(nonce, ciphertext, associated_data)