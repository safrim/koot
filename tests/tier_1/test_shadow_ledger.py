# tests/tier_1/test_shadow_ledger.py
import os
import threading
import pytest
from koot.identity.ledger import ShadowLedger

@pytest.fixture
def master_key():
    return os.urandom(32)

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "shadow_ledger.enc")

def test_shadow_ledger_initialization(db_path, master_key):
    ledger = ShadowLedger(db_path, master_key)
    assert os.path.exists(db_path), "Shadow Ledger file was not created"
    
def test_add_and_get_tenant(db_path, master_key):
    ledger = ShadowLedger(db_path, master_key)
    ledger.add_tenant("hash123", "Operative_Alpha", ["read", "write"], "escrowed_hex_data")
    
    tenant = ledger.get_tenant("hash123")
    assert tenant is not None
    assert tenant["tenant_id"] == "Operative_Alpha"
    assert tenant["locked"] is False

def test_update_tenant_status(db_path, master_key):
    ledger = ShadowLedger(db_path, master_key)
    ledger.add_tenant("hash123", "Operative_Alpha", ["read"], "escrow")
    ledger.update_tenant_status("hash123", True)
    
    tenant = ledger.get_tenant("hash123")
    assert tenant["locked"] is True

def test_decryption_failure_with_wrong_key(db_path, master_key):
    ledger = ShadowLedger(db_path, master_key)
    ledger.add_tenant("hash_target", "Operative_Beta", [], "escrow")
    
    wrong_key = os.urandom(32)
    ledger_wrong = ShadowLedger(db_path, wrong_key)
    
    with pytest.raises(ValueError, match="decryption failed"):
        ledger_wrong.get_tenant("hash_target")

def test_thread_safety_concurrent_writes(db_path, master_key):
    ledger = ShadowLedger(db_path, master_key)
    
    def worker(i):
        ledger.add_tenant(f"hash_{i}", f"User_{i}", ["read"], f"escrow_{i}")
        
    threads = []
    # Spawn 50 simultaneous threads trying to modify the same encrypted JSON
    for i in range(50):
        t = threading.Thread(target=worker, args=(i,))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    # Verify all tenants were written successfully without data corruption
    for i in range(50):
        tenant = ledger.get_tenant(f"hash_{i}")
        assert tenant is not None, f"Tenant hash_{i} was lost during concurrent writes"
        assert tenant["tenant_id"] == f"User_{i}"