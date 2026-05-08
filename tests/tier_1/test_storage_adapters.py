# tests/tier_1/test_storage_adapters.py
import pytest
import os
from koot.storage.adapters.local_fs import LocalFileSystemAdapter
from koot.storage.adapters.sqlite_db import SQLiteAdapter

# --- Fixtures ---

@pytest.fixture
def local_fs_adapter(tmp_path):
    """Provides a LocalFileSystemAdapter using a temporary directory."""
    storage_dir = tmp_path / "koot_storage_test"
    # Providing a test salt
    return LocalFileSystemAdapter(base_directory=str(storage_dir), system_salt=b"test_salt_123")

@pytest.fixture
def sqlite_adapter(tmp_path):
    """Provides an SQLiteAdapter using a temporary database file."""
    db_file = tmp_path / "test_koot.db"
    return SQLiteAdapter(db_path=str(db_file), system_salt=b"test_salt_123")

# --- Test Data ---
TEST_TENANT = "Operative_Alpha"
TEST_KEY = "chunk_001_deadbeef"
TEST_DATA = b"This is simulated encrypted binary chunk data \x00\x01\x02"

# --- Cryptographic Obfuscation Tests ---

def test_secure_key_derivation_obfuscation(local_fs_adapter):
    """Ensures that the tenant_id is cryptographically hashed and not stored in plaintext."""
    secure_key_alpha = local_fs_adapter.derive_secure_key("Operative_Alpha", TEST_KEY)
    secure_key_beta = local_fs_adapter.derive_secure_key("Operative_Beta", TEST_KEY)
    
    # Assert keys are unique per tenant
    assert secure_key_alpha != secure_key_beta
    
    # Assert plaintext metadata leaked nowhere in the generated key
    assert "Operative_Alpha" not in secure_key_alpha
    assert "Operative_Beta" not in secure_key_beta
    assert secure_key_alpha.endswith(TEST_KEY)

# --- Local File System Adapter Tests ---

def test_local_fs_write_and_read(local_fs_adapter):
    assert local_fs_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA) is True
    retrieved_data = local_fs_adapter.read(TEST_TENANT, TEST_KEY)
    assert retrieved_data == TEST_DATA

def test_local_fs_read_nonexistent(local_fs_adapter):
    assert local_fs_adapter.read(TEST_TENANT, "does_not_exist") is None

def test_local_fs_exists(local_fs_adapter):
    local_fs_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA)
    assert local_fs_adapter.exists(TEST_TENANT, TEST_KEY) is True
    assert local_fs_adapter.exists(TEST_TENANT, "ghost_key") is False

def test_local_fs_delete(local_fs_adapter):
    local_fs_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA)
    
    assert local_fs_adapter.delete(TEST_TENANT, TEST_KEY) is True
    assert local_fs_adapter.exists(TEST_TENANT, TEST_KEY) is False
    assert local_fs_adapter.delete(TEST_TENANT, "ghost_key") is False

# --- SQLite Adapter Tests ---

def test_sqlite_write_and_read(sqlite_adapter):
    assert sqlite_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA) is True
    retrieved_data = sqlite_adapter.read(TEST_TENANT, TEST_KEY)
    assert retrieved_data == TEST_DATA

def test_sqlite_overwrite(sqlite_adapter):
    sqlite_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA)
    new_data = b"Updated binary data"
    assert sqlite_adapter.write(TEST_TENANT, TEST_KEY, new_data) is True
    assert sqlite_adapter.read(TEST_TENANT, TEST_KEY) == new_data

def test_sqlite_exists(sqlite_adapter):
    sqlite_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA)
    assert sqlite_adapter.exists(TEST_TENANT, TEST_KEY) is True
    assert sqlite_adapter.exists(TEST_TENANT, "ghost_key") is False

def test_sqlite_delete(sqlite_adapter):
    sqlite_adapter.write(TEST_TENANT, TEST_KEY, TEST_DATA)
    assert sqlite_adapter.delete(TEST_TENANT, TEST_KEY) is True
    assert sqlite_adapter.exists(TEST_TENANT, TEST_KEY) is False