# koot/crypto/combiner/hkdf.py
import os
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import AlreadyFinalized

class HybridCombiner:
    """
    Session 7: The Hybrid Combiner
    [Engineered Countermeasure: The KDF Standard & Length Prefixing]
    
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
        
        :param classical_key: The symmetric key from AES/Argon2id.
        :param quantum_key: The shared secret from ML-KEM (Kyber).
        :param salt: Optional cryptographic salt. If None, HKDF safely handles it.
        :param info: Contextual binding data for the Expansion phase.
        :param length: Output length of the final key (32 bytes for AES-256).
        :return: A uniformly random cryptographic key.
        """
        # Type enforcement
        if not isinstance(classical_key, bytes) or not isinstance(quantum_key, bytes):
            raise TypeError("Both classical and quantum keys must be raw bytes.")

        # Step 1: Length-Prefixed Concatenation (Countermeasure for Collision Attacks)
        # Format: [4-byte Length of Classical][Classical Key][4-byte Length of Quantum][Quantum Key]
        len_c = struct.pack(">I", len(classical_key))
        len_q = struct.pack(">I", len(quantum_key))
        
        combined_key_material = len_c + classical_key + len_q + quantum_key

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