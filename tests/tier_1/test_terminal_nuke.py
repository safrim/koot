import pytest
import os
import sys
from argon2 import PasswordHasher
from koot.identity.derivation.pipeline import EntropyPipeline
from koot.identity.ledger import ShadowLedger

def test_terminal_key_shreds_and_exits(tmp_path):
    # 1. Setup a dummy Shadow Ledger
    db_path = tmp_path / "shadow_ledger.json"
    ledger = ShadowLedger(str(db_path), b"dummy_master_key_32_bytes_long!")
    
    # Ensure DB exists and has data/size on disk
    assert os.path.exists(str(db_path))
    
    # 2. Setup the Entropy Pipeline with Terminal Key
    pipeline = EntropyPipeline()
    ph = PasswordHasher()
    
    terminal_pwd = "password123_reversed"
    terminal_hash = ph.hash(terminal_pwd)
    
    pipeline.set_terminal_hash(terminal_hash)
    pipeline.register_nuke_callback(ledger.shred)
    
    # Mock `go_cold` just to assert it gets called (since C-Enclave may not be compiled in CI)
    go_cold_called = False
    original_go_cold = pipeline.go_cold
    def mock_go_cold():
        nonlocal go_cold_called
        go_cold_called = True
        original_go_cold()
    pipeline.go_cold = mock_go_cold
    
    # 3. Trigger the Terminal Key
    # We use pytest.raises to catch the sys.exit(86) so it doesn't actually kill the test runner
    with pytest.raises(SystemExit) as excinfo:
        pipeline.derive_and_lock_key(terminal_pwd)
        
    # 4. Verify Outcomes
    assert excinfo.value.code == 86, "Process did not exit with the Nuke code (86)"
    assert go_cold_called is True, "C-Enclave memory was not flushed"
    assert not os.path.exists(str(db_path)), "Shadow Ledger was not shredded from the disk"