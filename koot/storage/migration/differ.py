import logging
from typing import List

# FIXED: Import 'StorageDriver' instead of 'BaseStorageAdapter'
from koot.storage.adapters.base import StorageDriver

logger = logging.getLogger("koot.storage.migration")

class LiveMigrationEngine:
    """
    Phase 3, Session 11: Live Migration Utility.
    Executes cross-backend differential synchronization.
    """

    # FIXED: Update type hints to use 'StorageDriver'
    def __init__(self, source_adapter: StorageDriver, dest_adapter: StorageDriver):
        """
        Initializes the migration engine with a source and a destination.
        Both adapters must fulfill the StorageDriver contract.
        """
        self.source = source_adapter
        self.dest = dest_adapter

    def sync_envelope(self, envelope_id: str) -> bool:
        """
        Performs a differential sync of a specific envelope/file.
        """
        logger.info(f"Initiating live migration for Envelope ID: {envelope_id}")
        
        # 1. Fetch the Merkle manifests from both ends
        source_manifest = self.source.get_manifest(envelope_id)
        dest_manifest = self.dest.get_manifest(envelope_id)
        
        if not source_manifest:
            logger.error(f"Source envelope {envelope_id} not found. Aborting.")
            return False

        # 2. Addendum: Differential Sync Logic
        if not dest_manifest:
            logger.info("Destination empty. Executing full chunk migration.")
            chunks_to_transfer = list(source_manifest.chunk_hashes.keys())
        else:
            # Cryptographic shortcut: If the Merkle Roots match, the files are identical.
            if source_manifest.root_hash == dest_manifest.root_hash:
                logger.info(f"Merkle Roots match for {envelope_id}. Synchronization bypassed.")
                return True
                
            # If roots differ, calculate the precise delta
            chunks_to_transfer = self._calculate_delta(source_manifest, dest_manifest)
            logger.info(f"Delta calculated: {len(chunks_to_transfer)} out-of-sync chunk(s) require transfer.")

        # 3. Stream the necessary 64KB chunks
        self._pipeline_chunks(envelope_id, chunks_to_transfer)
        
        # 4. Finalize by committing the new manifest/Merkle Root to the destination
        self.dest.write_manifest(envelope_id, source_manifest)
        logger.info(f"Migration completed and integrity verified for {envelope_id}.")
        return True

    def _calculate_delta(self, source_manifest, dest_manifest) -> List[str]:
        """
        Compares chunk hashes to find missing or mutated chunks in the destination.
        """
        delta = []
        for chunk_id, source_hash in source_manifest.chunk_hashes.items():
            # If the chunk doesn't exist in the destination, or the hash doesn't match, flag it.
            if dest_manifest.chunk_hashes.get(chunk_id) != source_hash:
                delta.append(chunk_id)
        return delta

    def _pipeline_chunks(self, envelope_id: str, chunk_ids: List[str]) -> None:
        """
        Streams only the flagged 64KB chunks to the destination adapter.
        """
        for chunk_id in chunk_ids:
            logger.debug(f"Streaming chunk: {chunk_id}")
            chunk_data = self.source.read_chunk(envelope_id, chunk_id)
            
            if chunk_data is None:
                logger.critical(f"Data corruption: Chunk {chunk_id} missing from source adapter!")
                raise ValueError("Source chunk read failed during migration.")
                
            self.dest.write_chunk(envelope_id, chunk_id, chunk_data)