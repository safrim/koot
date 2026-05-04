import oqs
import ctypes

class KyberKEM:
    """
    Post-Quantum Key Encapsulation Mechanism using ML-KEM (Kyber).
    Provides quantum-resistant shared secret generation.
    """
    
    ALGORITHM = "Kyber768"

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(KyberKEM.ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            return public_key, secret_key

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(KyberKEM.ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
            return ciphertext, shared_secret

    @staticmethod
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        with oqs.KeyEncapsulation(KyberKEM.ALGORITHM) as kem:
            # Convert Python bytes to a C-array to prevent memory-freeing crashes
            c_secret_key = (ctypes.c_uint8 * len(secret_key)).from_buffer_copy(secret_key)
            kem.secret_key = c_secret_key
            
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret