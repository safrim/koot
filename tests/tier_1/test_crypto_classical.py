# tests/tier_1/test_crypto_classical.py
import unittest
import os
from koot.crypto.classical.fallback import SoftwareAESGCM
from koot.crypto.classical.accelerated import HardwareAESGCM
from cryptography.exceptions import InvalidTag

class TestClassicalCrypto(unittest.TestCase):

    def setUp(self):
        # AES-256 requires a 32-byte key
        self.key = os.urandom(32)
        self.plaintext = b"Highly confidential payload data."
        self.associated_data = b"EnvelopeHeaderData_v1"

    def test_software_aes_gcm_lifecycle(self):
        """Test full encrypt/decrypt cycle for the software fallback."""
        ciphertext, nonce = SoftwareAESGCM.encrypt(self.key, self.plaintext, self.associated_data)
        
        # Ensure ciphertext is not plaintext
        self.assertNotEqual(ciphertext, self.plaintext)
        
        decrypted = SoftwareAESGCM.decrypt(self.key, nonce, ciphertext, self.associated_data)
        self.assertEqual(decrypted, self.plaintext)

    def test_hardware_aes_gcm_lifecycle(self):
        """Test full encrypt/decrypt cycle for the hardware-accelerated driver."""
        ciphertext, nonce = HardwareAESGCM.encrypt(self.key, self.plaintext, self.associated_data)
        
        self.assertNotEqual(ciphertext, self.plaintext)
        
        decrypted = HardwareAESGCM.decrypt(self.key, nonce, ciphertext, self.associated_data)
        self.assertEqual(decrypted, self.plaintext)

    def test_aead_tamper_protection(self):
        """Verify that altering the ciphertext or associated data raises an InvalidTag error."""
        ciphertext, nonce = SoftwareAESGCM.encrypt(self.key, self.plaintext, self.associated_data)
        
        # Tamper with the ciphertext (flip a bit)
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0xFF
        
        with self.assertRaises(InvalidTag):
            SoftwareAESGCM.decrypt(self.key, nonce, bytes(tampered_ciphertext), self.associated_data)
            
        # Tamper with Associated Data
        with self.assertRaises(InvalidTag):
            SoftwareAESGCM.decrypt(self.key, nonce, ciphertext, b"FakeHeaderData")

if __name__ == '__main__':
    unittest.main()