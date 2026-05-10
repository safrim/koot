import os
import hashlib
from typing import Union
from koot.storage.adapters.base import StorageDriver
from koot.storage.adapters.local_fs import LocalFileSystemAdapter
from koot.storage.adapters.sqlite_db import SQLiteAdapter
from koot.storage.chunking.engine import ChunkingEngine
from koot.core.envelope.envelope import SecretEnvelope
from koot.identity.ledger import ShadowLedger

class StoragePipeline:
    def __init__(self, primary_adapter: StorageDriver, ledger: ShadowLedger):
        """
        Initializes the storage orchestrator.
        """
        self.adapter = primary_adapter
        self.ledger = ledger
        self.chunk_size = 64 * 1024  # 64KB chunks

    def save_secret(self, tenant_id: str, secret_key: str, payload: bytes) -> str:
        """
        Chunks a raw payload, encrypts it via an Envelope, and writes to the adapter.
        """
        # 1. Obfuscate the storage key to prevent plaintext metadata leakage
        obfuscated_id = hashlib.blake2b(f"{tenant_id}:{secret_key}".encode(), digest_size=16).hexdigest()
        
        # 2. Chunk the payload (assuming ChunkingEngine handles streaming/splitting)
        chunks = ChunkingEngine.split(payload, self.chunk_size)
        
        # 3. Create Envelopes and save via adapter
        manifest = []
        for index, chunk in enumerate(chunks):
            chunk_id = f"{obfuscated_id}_part_{index}"
            envelope = SecretEnvelope.wrap(chunk)
            self.adapter.write(tenant_id, chunk_id, envelope.serialize())
            manifest.append(chunk_id)
            
        # 4. Index in the Shadow Ledger
        self.ledger.update_index(tenant_id, secret_key, manifest)
        
        return obfuscated_id

    def retrieve_secret(self, tenant_id: str, secret_key: str) -> bytes:
        """
        Retrieves chunks from the adapter, unwraps Envelopes, and reconstructs the payload.
        """
        manifest = self.ledger.get_index(tenant_id, secret_key)
        if not manifest:
            raise ValueError("Secret not found in Shadow Ledger.")
            
        reconstructed = bytearray()
        for chunk_id in manifest:
            raw_data = self.adapter.read(tenant_id, chunk_id)
            envelope = SecretEnvelope.deserialize(raw_data)
            reconstructed.extend(envelope.unwrap())
            
        return bytes(reconstructed)