import unittest
from koot.crypto.post_quantum.kyber import KyberKEM

class TestPQCReality(unittest.TestCase):
    """
    Verifies that the underlying PQC library is executing real ML-KEM math
    by enforcing strict byte-size checks on the cryptographic outputs.
    """

    def test_kyber768_cryptographic_dimensions(self):
        # 1. Generate the lattice-based keys
        pub_key, sec_key = KyberKEM.generate_keypair()
        
        # 2. Encapsulate a shared secret
        ciphertext, shared_secret_sender = KyberKEM.encapsulate(pub_key)
        
        # 3. Assert exact mathematical sizes for Kyber-768
        self.assertEqual(len(pub_key), 1184, "Public key must be exactly 1184 bytes")
        self.assertEqual(len(sec_key), 2400, "Secret key must be exactly 2400 bytes")
        self.assertEqual(len(ciphertext), 1088, "Ciphertext must be exactly 1088 bytes")
        self.assertEqual(len(shared_secret_sender), 32, "Shared secret must be exactly 32 bytes")
        
        # 4. Decapsulate and verify match
        shared_secret_receiver = KyberKEM.decapsulate(ciphertext, sec_key)
        self.assertEqual(shared_secret_sender, shared_secret_receiver, "Decapsulated secret must match sender secret")

if __name__ == '__main__':
    unittest.main(verbosity=2)