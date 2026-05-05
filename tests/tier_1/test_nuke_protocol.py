import pytest
import time
from koot.governance.override.nuke import NukeProtocol

def test_nuke_trigger(tmp_path):
    vault = tmp_path / "vault.db"
    vault.write_text("secrets")
    
    nuke = NukeProtocol(target_path=str(vault))
    nuke.arm(timeout_seconds=1)
    
    time.sleep(1.5)
    
    assert not vault.exists()
    assert nuke.is_armed == False