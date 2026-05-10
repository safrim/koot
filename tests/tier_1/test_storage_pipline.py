import pytest
import os
from unittest.mock import patch, MagicMock
from koot.storage.pipeline import StoragePipeline
from koot.storage.adapters.local_fs import LocalFileSystemAdapter
from koot.identity.ledger import ShadowLedger
from koot.storage.chunking.engine import AdaptiveChunker

class MockEnvironmentSensor:
    def is_memory_low(self): return False

@patch('koot.storage.pipeline.SecretEnvelope')
def test_storage_pipeline_orchestration(MockEnvelopeClass, tmp_path):
    db_path = str(tmp_path / "shadow.json")
    storage_path = str(tmp_path / "vault")
    os.makedirs(storage_path, exist_ok=True)
    
    mock_envelope = MagicMock()
    mock_envelope.serialize.return_value = b'mock_blob'
    MockEnvelopeClass.wrap.return_value = mock_envelope
    
    ledger = ShadowLedger(db_path, b"dummy_master_key_exactly_32_byte")
    adapter = LocalFileSystemAdapter(base_directory=storage_path)
    chunker = AdaptiveChunker(environment_sensor=MockEnvironmentSensor())
    pipeline = StoragePipeline(primary_adapter=adapter, ledger=ledger, chunker=chunker)
    
    tenant_id = "Operative_Alpha"
    secret_key = "my_secret"
    payload = b" Classified Data " * 1000 
    
    obfuscated_id = pipeline.save_secret(tenant_id, secret_key, payload)
    
    # Verification
    files = os.listdir(storage_path)
    assert len(files) > 0
    # Fix: Filenames start with tenant hash, so we check if obfuscated_id is PRESENT
    assert any(obfuscated_id in f for f in files)

    manifest = ledger.get_index(tenant_id, secret_key)
    assert manifest is not None
    assert len(manifest) == len(files)