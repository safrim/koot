import pytest
import time
import secrets
from koot.governance.override.nuke import NukeProtocol
from koot.governance.override.interlock import OverrideMatrix

@pytest.fixture
def admin_creds():
    token = secrets.token_hex(32)
    master_hash = secrets.token_hex(32)
    return token, master_hash, OverrideMatrix(token, master_hash)

def test_nuke_trigger(tmp_path, admin_creds):
    token, master_hash, matrix = admin_creds
    vault = tmp_path / "vault.db"
    vault.write_text("secrets")
    
    nuke = NukeProtocol(override_matrix=matrix, target_path=str(vault))
    # Authorized arming
    assert nuke.arm(1, token, master_hash) is True
    
    time.sleep(1.5)
    
    assert not vault.exists()
    assert nuke.is_armed is False

def test_authorized_heartbeat_and_disarm(tmp_path, admin_creds):
    token, master_hash, matrix = admin_creds
    vault = tmp_path / "vault.db"
    vault.write_text("secrets")
    
    nuke = NukeProtocol(override_matrix=matrix, target_path=str(vault))
    nuke.arm(2, token, master_hash)
    
    time.sleep(1)
    # Authorized heartbeat keeps it alive
    assert nuke.heartbeat(token, master_hash) is True
    
    # Authorized disarm
    assert nuke.disarm(token, master_hash) is True
    assert nuke.is_armed is False

def test_unauthorized_nuke_lifecycle_sub_user(tmp_path, admin_creds):
    token, master_hash, matrix = admin_creds
    vault = tmp_path / "vault.db"
    vault.write_text("secrets")
    
    sub_user_hash = secrets.token_hex(32)
    nuke = NukeProtocol(override_matrix=matrix, target_path=str(vault))
    
    # Sub-user should fail to arm
    assert nuke.arm(1, token, sub_user_hash) is False
    assert nuke.is_armed is False
    
    # Arm legitimately for the next tests
    nuke.arm(1, token, master_hash)
    
    # Sub-user should fail to heartbeat or disarm
    assert nuke.heartbeat(token, sub_user_hash) is False
    assert nuke.disarm(token, sub_user_hash) is False
    
    # Let it nuke to prove the sub-user couldn't stop it
    time.sleep(1.5)
    assert not vault.exists()

def test_authorized_trigger_now(tmp_path, admin_creds):
    token, master_hash, matrix = admin_creds
    vault = tmp_path / "vault.db"
    vault.write_text("secrets")
    
    nuke = NukeProtocol(override_matrix=matrix, target_path=str(vault))
    success = nuke.trigger_now(token, master_hash)
    
    assert success is True
    assert not vault.exists()

def test_unauthorized_trigger_now_sub_user(tmp_path, admin_creds):
    token, _, matrix = admin_creds
    vault = tmp_path / "vault.db"
    vault.write_text("secrets")
    
    nuke = NukeProtocol(override_matrix=matrix, target_path=str(vault))
    
    sub_user_hash = secrets.token_hex(32)
    success = nuke.trigger_now(token, sub_user_hash)
    
    assert success is False
    assert vault.exists()