import os
import pytest
from unittest.mock import patch
from argon2 import PasswordHasher
from koot.identity.derivation.pipeline import EntropyPipeline
from koot.identity.ledger import ShadowLedger

@patch('koot.identity.derivation.pipeline.ENCLAVE_AVAILABLE', True)
@patch('koot.identity.derivation.pipeline._enclave_lib')
def test_duress_protocol_pipeline_detection(mock_enclave):
    mock_enclave.allocate_secure_key.return_value = 1
    
    ph = PasswordHasher()
    duress_pwd = "rubber_hose_password"
    duress_hash = ph.hash(duress_pwd)
    
    pipeline_normal = EntropyPipeline()
    pipeline_normal.set_duress_hash(duress_hash)
    pipeline_normal.derive_and_lock_key("real_secure_password_123")
    assert pipeline_normal.is_duress_mode is False
    
    pipeline_duress = EntropyPipeline()
    pipeline_duress.set_duress_hash(duress_hash)
    pipeline_duress.derive_and_lock_key(duress_pwd)
    assert pipeline_duress.is_duress_mode is True

@patch('koot.identity.ledger.SoftwareAESGCM')
def test_shadow_ledger_decoy_routing(mock_aes, tmp_path):
    # Completely bypass the broken C-Library by forcing the mock 
    # to return valid 15-byte JSON instead of null bytes.
    mock_aes.encrypt.return_value = (b"mock_ciphertext", b"123456789012")
    mock_aes.decrypt.return_value = b'{"tenants": {}}'
    
    master_key = b"0123456789abcdef0123456789abcdef"
    
    # --- TEST 1: Normal Routing (Isolated Path) ---
    db_path_normal = str(tmp_path / "shadow_ledger_normal.json")
    ledger_normal = ShadowLedger(db_path_normal, master_key, is_duress_mode=False)
    assert "dummy" not in ledger_normal.db_path
    assert ledger_normal.db_path == db_path_normal
    assert os.path.exists(db_path_normal)
    
    # --- TEST 2: Decoy Routing (Isolated Path) ---
    db_path_duress = str(tmp_path / "shadow_ledger_target.json")
    ledger_duress = ShadowLedger(db_path_duress, master_key, is_duress_mode=True)
    assert "dummy" in ledger_duress.db_path
    assert ledger_duress.db_path == str(tmp_path / "shadow_ledger_target_dummy.json")
    
    # Verify Decoy DB works exactly like a real one
    ledger_duress.add_tenant("hash123", "decoy_user", ["read"], "escrow_hex")
    assert os.path.exists(ledger_duress.db_path)
    
    # Assert the real file was NOT created during duress mode
    assert not os.path.exists(db_path_duress), "Real database file was accidentally created in duress mode"