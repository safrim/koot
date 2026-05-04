import unittest
from koot.crypto.post_quantum.kyber import KyberKEM

class TestPQCLayer(unittest.TestCase):

    def test_kyber_keypair_generation(self):
        """Test that a valid public and secret key are generated."""
        pub_key, sec_key = KyberKEM.generate_keypair()
        
        self.assertIsNotNone(pub_key)
        self.assertIsNotNone(sec_key)
        self.assertTrue(len(pub_key) > 0)
        self.assertTrue(len(sec_key) > 0)

    def test_encapsulation_decapsulation_lifecycle(self):
        """Test the full quantum-safe key exchange lifecycle."""
        # 1. Receiver generates keypair
        pub_key, sec_key = KyberKEM.generate_keypair()
        
        # 2. Sender generates shared secret and encapsulates it
        ciphertext, sender_shared_secret = KyberKEM.encapsulate(pub_key)
        
        # 3. Receiver decapsulates it
        receiver_shared_secret = KyberKEM.decapsulate(ciphertext, sec_key)
        
        # 4. Verify both sides have the exact same secret
        self.assertEqual(sender_shared_secret, receiver_shared_secret)

    def test_decapsulation_failure_on_bad_ciphertext(self):
        """Test that tampering with the ciphertext prevents decapsulation."""
        pub_key, sec_key = KyberKEM.generate_keypair()
        ciphertext, original_secret = KyberKEM.encapsulate(pub_key)
        
        # Tamper with the ciphertext (flip a bit)
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        
        # Implicit Rejection: Kyber doesn't always throw an error on bad ciphertext; 
        # it generates a pseudo-random DIFFERENT secret to prevent chosen-ciphertext attacks.
        # We must verify the resulting secret does NOT match the original.
        bad_secret = KyberKEM.decapsulate(bytes(tampered_ciphertext), sec_key)
        
        self.assertNotEqual(original_secret, bad_secret)

if __name__ == '__main__':
    unittest.main(verbosity=2)