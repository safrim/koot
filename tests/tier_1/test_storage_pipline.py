import pytest
import os
from koot.storage.pipeline import StoragePipeline
from koot.storage.adapters.local_fs import LocalFileSystemAdapter
from koot.identity.ledger import ShadowLedger

def test_storage_pipeline_orchestration(tmp_path):
    # Setup mock dependencies
    db_path = tmp_path / "shadow.json"
    storage_path = tmp_path / "vault"
    storage_path.mkdir()
    
    ledger = ShadowLedger(db_path, "dummy_master_key")
    adapter = LocalFileSystemAdapter(storage_dir=str(storage_path))
    pipeline = StoragePipeline(primary_adapter=adapter, ledger=ledger)
    
    tenant_id = "Operative_Alpha"
    secret_key = "my_secret"
    payload = b"This is a highly classified payload that will be securely chunked and wrapped." * 2000 # Larger than 64KB
    
    # 1. Test Save
    obfuscated_id = pipeline.save_secret(tenant_id, secret_key, payload)
    assert obfuscated_id is not None
    
    # Verify file was written to disk
    files_on_disk = os.listdir(storage_path)
    assert len(files_on_disk) > 0
    assert files_on_disk[0].startswith(obfuscated_id)
    
    # 2. Test Retrieval
    retrieved = pipeline.retrieve_secret(tenant_id, secret_key)
    assert retrieved == payload