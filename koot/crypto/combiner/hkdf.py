# koot/crypto/combiner/hkdf.py
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import AlreadyFinalized

class HybridCombiner:
    """
    Session 7: The Hybrid Combiner
    [Engineered Countermeasure: The KDF Standard]
    
    Acts as the cryptographic "blender" for koot, safely fusing classical 
    and post-quantum keys into a single, unbreakable Master Session Key using HKDF.
    """
    
    @staticmethod
    def derive_session_key(
        classical_key: bytes, 
        quantum_key: bytes, 
        salt: bytes = None, 
        info: bytes = b"koot-hybrid-master-key-v1",
        length: int = 32
    ) -> bytes:
        """
        Safely extracts and expands a session key from combined entropy.
        
        :param classical_key: The 32-byte key from AES/Argon2id.
        :param quantum_key: The 32-byte shared secret from ML-KEM (Kyber).
        :param salt: Optional cryptographic salt. If None, HKDF safely handles it.
        :param info: Contextual binding data for the Expansion phase.
        :param length: Output length of the final key (32 bytes for AES-256).
        :return: A uniformly random cryptographic key.
        """
        # Step 1: Concatenate the two distinct entropy sources
        combined_key_material = classical_key + quantum_key

        # Step 2: Initialize HKDF using SHA-3 (as requested in the architecture plan)
        hkdf = HKDF(
            algorithm=hashes.SHA3_256(),
            length=length,
            salt=salt,
            info=info,
        )
        
        # Step 3: Perform the "Extract and Expand" to generate the final session key
        session_key = hkdf.derive(combined_key_material)
        
        return session_key