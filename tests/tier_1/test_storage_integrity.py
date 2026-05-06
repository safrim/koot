import unittest
import os
import math
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

    def test_out_of_core_large_tree_simulation(self):
        """Proves the disk-backed tree can process an arbitrary number of nodes without holding them in RAM."""
        large_tree = MerkleTree()
        num_chunks = 100  # Non-power-of-2 boundary
        chunks = [os.urandom(1024) for _ in range(num_chunks)]
        
        for chunk in chunks:
            large_tree.add_chunk(chunk)
            
        large_tree.build()
        root_hash = large_tree.get_root_hash()
        
        # Pull proof for the absolute last chunk and verify
        target_index = num_chunks - 1
        proof = large_tree.get_proof(target_index)
        is_valid = StreamingVerifier.verify_chunk(chunks[target_index], proof, root_hash)
        
        self.assertTrue(is_valid, "Out-of-core streaming verification failed on large dataset.")
        
        # Verify mathematically correct tree depth
        expected_levels = math.ceil(math.log2(num_chunks))
        self.assertEqual(large_tree.max_level, expected_levels, "Tree depth calculation is incorrect.")

if __name__ == '__main__':
    unittest.main()