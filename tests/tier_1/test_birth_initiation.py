import os
import pytest
from pathlib import Path
from koot.identity.ledger import ShadowLedger
from koot.identity.derivation.pipeline import EntropyPipeline

def test_cryptographic_initiation_success(tmp_path):
    """Verifies that the ledger is correctly initialized and readable with the derived key[cite: 33]."""
    ledger_file = tmp_path / "ledger.shadow"
    password = "test_master_pwd"
    salt = os.urandom(16)
    
    # Simulate the derivation process [cite: 21]
    pipeline = EntropyPipeline()
    import argon2.low_level
    raw_key = argon2.low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=pipeline.time_cost,
        memory_cost=pipeline.memory_cost,
        parallelism=pipeline.parallelism,
        hash_len=pipeline.hash_len,
        type=argon2.low_level.Type.ID
    )

    # Create the ledger [cite: 33]
    ledger = ShadowLedger(str(ledger_file), raw_key)
    assert ledger_file.exists()
    
    # Reload and verify integrity
    reloaded_ledger = ShadowLedger(str(ledger_file), raw_key)
    db_state = reloaded_ledger._load_db()
    assert db_state == {"tenants": {}}

def test_initiation_tamper_failure(tmp_path):
    """Ensures that access is denied if an incorrect master key is used[cite: 33]."""
    ledger_file = tmp_path / "ledger.shadow"
    valid_key = os.urandom(32)
    invalid_key = os.urandom(32)
    
    # Initialize validly
    ShadowLedger(str(ledger_file), valid_key)
    
    # Attempt access with invalid key
    with pytest.raises(ValueError, match="Shadow Ledger decryption failed"):
        bad_ledger = ShadowLedger(str(ledger_file), invalid_key)
        bad_ledger._load_db()