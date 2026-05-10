import pytest
import json
import time
from koot.governance.audit.log import AuditLogger

def test_audit_log_rotation_integrity(tmp_path):
    log_dir = tmp_path / "logs"
    
    # Set a large max_size to prevent recursive cascading rotations during the test
    logger = AuditLogger(log_dir=str(log_dir), max_size_bytes=1024 * 1024)
    
    logger.log("action_1", "admin")
    logger.log("action_2", "admin")
    
    # Trigger rotation manually to cleanly test the background thread hand-off
    logger.rotate()
    
    # Wait briefly for the background sealing thread to complete its hashing
    time.sleep(0.1)
    
    sealed_files = list(log_dir.glob("*.sealed"))
    assert len(sealed_files) == 1
    
    with open(logger.current_log_path, "r") as f:
        lines = f.readlines()
        
        # The new epoch starts with a PENDING state due to async rotation
        first_line = json.loads(lines[0])
        assert first_line["event"] == "EPOCH_START"
        assert first_line["prev_log_hash"] == "PENDING_ASYNC_CALCULATION"

        # The background thread should have injected the EPOCH_SEALED event securely
        last_line = json.loads(lines[-1])
        assert last_line["action"] == "EPOCH_SEALED"
        assert "final_hash" in last_line["details"]
        assert last_line["details"]["sealed_file"] == sealed_files[0].name