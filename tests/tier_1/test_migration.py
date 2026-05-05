import unittest
from unittest.mock import MagicMock, call
import logging

# Disable logging output during tests for clean console
logging.disable(logging.CRITICAL)

from koot.storage.migration.differ import LiveMigrationEngine

class MockManifest:
    def __init__(self, root_hash, chunk_hashes):
        self.root_hash = root_hash
        self.chunk_hashes = chunk_hashes

class TestLiveMigrationEngine(unittest.TestCase):
    def setUp(self):
        # Create mock Source and Destination Adapters
        self.source_adapter = MagicMock()
        self.dest_adapter = MagicMock()
        self.engine = LiveMigrationEngine(self.source_adapter, self.dest_adapter)
        self.envelope_id = "env_live_test_001"

    def test_full_migration_empty_destination(self):
        """Test behavior when the destination has no pre-existing envelope."""
        # Source has 3 chunks, Dest has nothing
        source_manifest = MockManifest("root_ABC", {"chunk_1": "hash_1", "chunk_2": "hash_2", "chunk_3": "hash_3"})
        
        self.source_adapter.get_manifest.return_value = source_manifest
        self.dest_adapter.get_manifest.return_value = None
        self.source_adapter.read_chunk.return_value = b"dummy_data"

        result = self.engine.sync_envelope(self.envelope_id)

        self.assertTrue(result)
        # Verify 3 chunks were read and written
        self.assertEqual(self.source_adapter.read_chunk.call_count, 3)
        self.assertEqual(self.dest_adapter.write_chunk.call_count, 3)
        # Verify manifest was written to dest
        self.dest_adapter.write_manifest.assert_called_once_with(self.envelope_id, source_manifest)

    def test_migration_bypass_matching_roots(self):
        """Test the O(1) bypass when Merkle Roots are identical."""
        identical_manifest = MockManifest("root_MATCH", {"chunk_1": "hash_1"})
        
        self.source_adapter.get_manifest.return_value = identical_manifest
        self.dest_adapter.get_manifest.return_value = identical_manifest

        result = self.engine.sync_envelope(self.envelope_id)

        self.assertTrue(result)
        # Verify ZERO chunks were read or written (Bandwidth/IO saved!)
        self.source_adapter.read_chunk.assert_not_called()
        self.dest_adapter.write_chunk.assert_not_called()

    def test_differential_sync_missing_chunk(self):
        """Test that only the mutated/missing chunk is transferred."""
        source_manifest = MockManifest("root_NEW", {"chunk_1": "hash_1", "chunk_2": "hash_2_MUTATED"})
        # Destination has chunk 1, but chunk 2 is old/wrong
        dest_manifest = MockManifest("root_OLD", {"chunk_1": "hash_1", "chunk_2": "hash_2_OLD"})
        
        self.source_adapter.get_manifest.return_value = source_manifest
        self.dest_adapter.get_manifest.return_value = dest_manifest
        self.source_adapter.read_chunk.return_value = b"new_mutated_data"

        result = self.engine.sync_envelope(self.envelope_id)

        self.assertTrue(result)
        
        # Verify ONLY chunk 2 was read and written
        self.source_adapter.read_chunk.assert_called_once_with(self.envelope_id, "chunk_2")
        self.dest_adapter.write_chunk.assert_called_once_with(self.envelope_id, "chunk_2", b"new_mutated_data")
        
        # Verify the new manifest was committed
        self.dest_adapter.write_manifest.assert_called_once_with(self.envelope_id, source_manifest)

    def test_source_envelope_not_found(self):
        """Test graceful failure if the source envelope doesn't exist."""
        self.source_adapter.get_manifest.return_value = None
        
        result = self.engine.sync_envelope(self.envelope_id)
        
        self.assertFalse(result)
        self.source_adapter.read_chunk.assert_not_called()

if __name__ == '__main__':
    unittest.main()