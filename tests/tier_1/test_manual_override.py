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

class MockShadowLedger:
    """Mock ledger to test the integration of localized freezes."""
    def __init__(self):
        self.locked_tenants = set()
        
    def lock_tenant_by_id(self, tenant_id: str) -> bool:
        self.locked_tenants.add(tenant_id)
        return True

def test_localized_freeze_authorized(admin_creds):
    token, master_hash, matrix = admin_creds
    ledger = MockShadowLedger()
    
    severed_tenants = []
    def mock_sever_sockets(tenant_id):
        severed_tenants.append(tenant_id)
        
    matrix.register_freeze_callback(mock_sever_sockets)
    
    # Trigger the freeze
    success = matrix.trigger_localized_freeze(token, master_hash, "Operative_Alpha", ledger)
    
    assert success is True
    assert "Operative_Alpha" in ledger.locked_tenants
    assert "Operative_Alpha" in severed_tenants

def test_localized_freeze_unauthorized(admin_creds):
    token, master_hash, matrix = admin_creds
    ledger = MockShadowLedger()
    sub_user_hash = secrets.token_hex(32) # Invalid master hash
    
    success = matrix.trigger_localized_freeze(token, sub_user_hash, "Operative_Alpha", ledger)
    
    assert success is False
    assert "Operative_Alpha" not in ledger.locked_tenants

# --- Updates for Provisioning Tests ---

# Update the MockShadowLedger to support the add_tenant method
class ExtendedMockShadowLedger(MockShadowLedger):
    def __init__(self):
        super().__init__()
        self.tenants = {}
        
    def add_tenant(self, cert_hash: str, tenant_id: str, permissions: list, escrowed_key: str):
        self.tenants[cert_hash] = {
            "tenant_id": tenant_id,
            "permissions": permissions,
            "escrowed_key": escrowed_key,
            "locked": False
        }

class MockEntropyPipeline:
    def generate_tenant_master_key(self) -> bytes:
        return b"mock_32_byte_tenant_key_00000000"
        
    def wrap_for_escrow(self, tenant_key: bytes, core_master_key: bytes) -> str:
        return "mock_escrowed_hex"

def test_provision_agent_authorized(admin_creds):
    token, master_hash, matrix = admin_creds
    ledger = ExtendedMockShadowLedger()
    pipeline = MockEntropyPipeline()
    core_master_key = b"mock_core_master_key_32_bytes_12"
    new_cert_hash = secrets.token_hex(32)
    
    success = matrix.provision_agent(
        token=token,
        client_cert_hash=master_hash,
        tenant_id="Operative_Delta",
        new_client_cert_hash=new_cert_hash,
        permissions=["credentials", "notes"],
        shadow_ledger=ledger,
        entropy_pipeline=pipeline,
        core_master_key=core_master_key
    )
    
    assert success is True
    assert new_cert_hash in ledger.tenants
    assert ledger.tenants[new_cert_hash]["tenant_id"] == "Operative_Delta"
    assert ledger.tenants[new_cert_hash]["escrowed_key"] == "mock_escrowed_hex"

def test_provision_agent_unauthorized(admin_creds):
    token, master_hash, matrix = admin_creds
    ledger = ExtendedMockShadowLedger()
    pipeline = MockEntropyPipeline()
    core_master_key = b"mock_core_master_key_32_bytes_12"
    new_cert_hash = secrets.token_hex(32)
    sub_user_hash = secrets.token_hex(32) # Invalid authority
    
    success = matrix.provision_agent(
        token=token,
        client_cert_hash=sub_user_hash, 
        tenant_id="Operative_Delta",
        new_client_cert_hash=new_cert_hash,
        permissions=["credentials", "notes"],
        shadow_ledger=ledger,
        entropy_pipeline=pipeline,
        core_master_key=core_master_key
    )
    
    assert success is False
    assert new_cert_hash not in ledger.tenants