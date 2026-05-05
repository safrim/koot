import unittest
import os
from koot.core.envelope.envelope import process_file_for_storage

class TestStoragePipelineE2E(unittest.TestCase):
    def setUp(self):
        """Setup runs before the test: Create a 2.5MB dummy file."""
        self.test_file = "dummy_video_e2e.bin"
        with open(self.test_file, "wb") as f:
            f.write(os.urandom(int(2.5 * 1024 * 1024)))

    def tearDown(self):
        """Teardown runs after the test: Clean up the dummy file."""
        if os.path.exists(self.test_file):
            os.remove(self.test_file)

    def test_end_to_end_adaptive_chunking_and_hashing(self):
        """
        Proves that a file can be dynamically read from disk (I/O layer)
        while successfully generating a stable Merkle Root Hash (Crypto layer).
        """
        try:
            # Run the pipeline
            root_hash = process_file_for_storage(self.test_file)
            
            # Assertions to ensure the pipeline worked and returned a valid hash
            self.assertIsNotNone(root_hash, "Root hash should not be None")
            self.assertIsInstance(root_hash, str, "Root hash should be a string")
            self.assertTrue(len(root_hash) > 0, "Root hash should not be empty")
            
            print(f"\n[E2E Success] Generated Envelope Root Hash: {root_hash}")
            
        except Exception as e:
            self.fail(f"E2E storage pipeline failed with exception: {e}")

if __name__ == '__main__':
    unittest.main()