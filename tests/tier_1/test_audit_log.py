import pytest
import json
from koot.governance.audit.log import AuditLogger

def test_audit_log_rotation_integrity(tmp_path):
    log_dir = tmp_path / "logs"
    # Small max_size to force rotation
    logger = AuditLogger(log_dir=str(log_dir), max_size_bytes=100)
    
    logger.log("action_1", "admin")
    logger.log("action_2", "admin") # Triggers rotation
    
    sealed_files = list(log_dir.glob("*.sealed"))
    assert len(sealed_files) == 1
    
    with open(logger.current_log_path, "r") as f:
        first_line = json.loads(f.readline())
        assert first_line["event"] == "EPOCH_START"
        assert first_line["prev_log_hash"] != "0" * 64