import hashlib
from koot.storage.adapters.base import StorageDriver
from koot.core.envelope.envelope import SecretEnvelope
from koot.identity.ledger import ShadowLedger
from koot.storage.chunking.engine import AdaptiveChunker

class StoragePipeline:
    def __init__(self, primary_adapter: StorageDriver, ledger: ShadowLedger, chunker: AdaptiveChunker):
        self.adapter = primary_adapter
        self.ledger = ledger
        self.chunker = chunker

    def save_secret(self, tenant_id: str, secret_key: str, payload: bytes) -> str:
        # Obfuscate the secret key
        obfuscated_id = hashlib.blake2b(f"{tenant_id}:{secret_key}".encode(), digest_size=16).hexdigest()
        
        # Use AdaptiveChunker for in-memory bytes
        chunks = list(self.chunker.process_bytes(payload))
        
        manifest = []
        for index, chunk in enumerate(chunks):
            chunk_id = f"{obfuscated_id}_part_{index}"
            envelope = SecretEnvelope.wrap(chunk)
            self.adapter.write(tenant_id, chunk_id, envelope.serialize())
            manifest.append(chunk_id)
            
        self.ledger.update_index(tenant_id, secret_key, manifest)
        return obfuscated_id

    def retrieve_secret(self, tenant_id: str, secret_key: str) -> bytes:
        manifest = self.ledger.get_index(tenant_id, secret_key)
        if not manifest:
            raise ValueError("Secret not found.")
            
        reconstructed = bytearray()
        for chunk_id in manifest:
            raw_data = self.adapter.read(tenant_id, chunk_id)
            envelope = SecretEnvelope.deserialize(raw_data)
            reconstructed.extend(envelope.unwrap())
            
        return bytes(reconstructed)