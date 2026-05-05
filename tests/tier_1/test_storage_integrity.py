import unittest
import os
from koot.storage.integrity.merkle import MerkleTree, StreamingVerifier

class TestMerkleIntegrity(unittest.TestCase):
    def setUp(self):
        # Simulate four 64KB chunks
        self.chunks = [os.urandom(64 * 1024) for _ in range(4)]
        
        self.tree = MerkleTree()
        for chunk in self.chunks:
            self.tree.add_chunk(chunk)
            
        self.tree.build()
        self.root_hash = self.tree.get_root_hash()

    def test_streaming_verification_success(self):
        """Proves we can verify a single chunk securely without the rest of the file."""
        target_index = 2
        target_chunk = self.chunks[target_index]
        
        proof = self.tree.get_proof(target_index)
        
        is_valid = StreamingVerifier.verify_chunk(target_chunk, proof, self.root_hash)
        self.assertTrue(is_valid, "Streaming verification failed for valid chunk!")

    def test_streaming_verification_tamper_detection(self):
        """Proves that a single flipped bit in a chunk fails verification immediately."""
        target_index = 1
        target_chunk = self.chunks[target_index]
        
        # Simulate Bit-Rot / Tampering
        tampered_chunk = bytearray(target_chunk)
        tampered_chunk[0] ^= 0xFF
        
        proof = self.tree.get_proof(target_index)
        
        is_valid = StreamingVerifier.verify_chunk(bytes(tampered_chunk), proof, self.root_hash)
        self.assertFalse(is_valid, "Streaming verification failed to catch tampered chunk!")

if __name__ == '__main__':
    unittest.main()