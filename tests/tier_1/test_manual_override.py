import pytest
import secrets
from koot.governance.override.interlock import OverrideMatrix

@pytest.fixture
def admin_creds():
    token = secrets.token_hex(32)
    master_hash = secrets.token_hex(32)
    return token, master_hash, OverrideMatrix(token, master_hash)

def test_unauthorized_halt_wrong_token(admin_creds):
    token, master_hash, matrix = admin_creds
    success = matrix.trigger_global_halt("wrong-token", master_hash)
    assert success is False
    assert matrix.is_halted is False

def test_unauthorized_halt_sub_user_context(admin_creds):
    # Simulates a sub-user with the right admin token but the wrong certificate
    token, master_hash, matrix = admin_creds
    sub_user_hash = secrets.token_hex(32)
    
    success = matrix.trigger_global_halt(token, sub_user_hash)
    assert success is False
    assert matrix.is_halted is False

def test_authorized_halt(admin_creds):
    token, master_hash, matrix = admin_creds
    success = matrix.trigger_global_halt(token, master_hash)
    assert success is True
    assert matrix.is_halted is True

def test_abort_callback_execution(admin_creds):
    token, master_hash, matrix = admin_creds
    aborted = False

    def emergency_stop():
        nonlocal aborted
        aborted = True

    matrix.register_abort_callback(emergency_stop)
    matrix.trigger_abort_all(token, master_hash)
    
    assert aborted is True

def test_abort_callback_blocked_for_sub_user(admin_creds):
    token, master_hash, matrix = admin_creds
    sub_user_hash = secrets.token_hex(32)
    aborted = False

    def emergency_stop():
        nonlocal aborted
        aborted = True

    matrix.register_abort_callback(emergency_stop)
    success = matrix.trigger_abort_all(token, sub_user_hash)
    
    assert success is False
    assert aborted is False

def test_reset_functionality(admin_creds):
    token, master_hash, matrix = admin_creds
    matrix.trigger_global_halt(token, master_hash)
    matrix.reset_halt(token, master_hash)
    assert matrix.is_halted is False