# tests/tier_1/test_crypto_combiner.py
import unittest
import os
from koot.crypto.combiner.hkdf import HybridCombiner

class TestHybridCombiner(unittest.TestCase):
    
    def setUp(self):
        # Simulate a 32-byte AES key and a 32-byte Kyber shared secret
        self.classical_key = os.urandom(32)
        self.quantum_key = os.urandom(32)
        self.salt = os.urandom(16)
        
    def test_hkdf_determinism(self):
        """
        Proves that identical classical and quantum keys, with the same salt,
        will consistently produce the exact same final session key.
        """
        key_1 = HybridCombiner.derive_session_key(
            self.classical_key, 
            self.quantum_key, 
            salt=self.salt
        )
        
        key_2 = HybridCombiner.derive_session_key(
            self.classical_key, 
            self.quantum_key, 
            salt=self.salt
        )
        
        self.assertEqual(len(key_1), 32, "The derived key must be exactly 32 bytes (256 bits).")
        self.assertEqual(key_1, key_2, "HKDF failed determinism check; keys do not match.")
        
    def test_hkdf_entropy_isolation(self):
        """
        Proves that changing even a single bit in EITHER the classical key 
        OR the quantum key results in a radically different final session key 
        (The Avalanche Effect).
        """
        original_key = HybridCombiner.derive_session_key(
            self.classical_key, 
            self.quantum_key, 
            salt=self.salt
        )
        
        # Tamper with the Classical Key
        tampered_classical = bytearray(self.classical_key)
        tampered_classical[0] ^= 0xFF
        
        classical_tamper_result = HybridCombiner.derive_session_key(
            bytes(tampered_classical), 
            self.quantum_key, 
            salt=self.salt
        )
        
        # Tamper with the Quantum Key
        tampered_quantum = bytearray(self.quantum_key)
        tampered_quantum[0] ^= 0xFF
        
        quantum_tamper_result = HybridCombiner.derive_session_key(
            self.classical_key, 
            bytes(tampered_quantum), 
            salt=self.salt
        )
        
        self.assertNotEqual(original_key, classical_tamper_result, "Classical key tampering failed to trigger the avalanche effect.")
        self.assertNotEqual(original_key, quantum_tamper_result, "Quantum key tampering failed to trigger the avalanche effect.")
        self.assertNotEqual(classical_tamper_result, quantum_tamper_result)

    def test_concatenation_collision_prevention(self):
        """
        [Countermeasure Verification]
        Proves that two distinct sets of keys that would normally concatenate 
        to the exact same byte string do NOT result in the same session key,
        thanks to strict length prefixing.
        """
        # Scenario: Two different pairs of keys that concatenate to b"123456"
        # Pair A: "123" + "456"
        c_key_a = b"123"
        q_key_a = b"456"
        
        # Pair B: "12" + "3456"
        c_key_b = b"12"
        q_key_b = b"3456"
        
        # Under raw concatenation, c_key_a + q_key_a == c_key_b + q_key_b
        # But our system should prevent this.
        
        key_a_result = HybridCombiner.derive_session_key(
            c_key_a, 
            q_key_a, 
            salt=self.salt
        )
        
        key_b_result = HybridCombiner.derive_session_key(
            c_key_b, 
            q_key_b, 
            salt=self.salt
        )
        
        self.assertNotEqual(
            key_a_result, 
            key_b_result, 
            "CRITICAL: Length-prefixing failed. The system is vulnerable to concatenation collision attacks."
        )

if __name__ == '__main__':
    unittest.main(verbosity=2)