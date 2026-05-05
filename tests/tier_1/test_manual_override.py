import pytest
import secrets
from koot.governance.override.interlock import OverrideMatrix

@pytest.fixture
def admin_creds():
    token = secrets.token_hex(32)
    return token, OverrideMatrix(token)

def test_unauthorized_halt(admin_creds):
    _, matrix = admin_creds
    success = matrix.trigger_global_halt("wrong-token")
    assert success is False
    assert matrix.is_halted is False

def test_authorized_halt(admin_creds):
    token, matrix = admin_creds
    success = matrix.trigger_global_halt(token)
    assert success is True
    assert matrix.is_halted is True

def test_abort_callback_execution(admin_creds):
    token, matrix = admin_creds
    aborted = False

    def emergency_stop():
        nonlocal aborted
        aborted = True

    matrix.register_abort_callback(emergency_stop)
    matrix.trigger_abort_all(token)
    
    assert aborted is True

def test_reset_functionality(admin_creds):
    token, matrix = admin_creds
    matrix.trigger_global_halt(token)
    matrix.reset_halt(token)
    assert matrix.is_halted is False