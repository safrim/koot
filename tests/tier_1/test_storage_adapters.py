# tests/tier_1/test_storage_adapters.py
import pytest
import os
from koot.storage.adapters.local_fs import LocalFileSystemAdapter
from koot.storage.adapters.sqlite_db import SQLiteAdapter

# --- Fixtures ---

@pytest.fixture
def local_fs_adapter(tmp_path):
    """Provides a LocalFileSystemAdapter using a temporary directory."""
    # tmp_path is a built-in pytest fixture that creates a unique temp dir per test
    storage_dir = tmp_path / "koot_storage_test"
    return LocalFileSystemAdapter(base_directory=str(storage_dir))

@pytest.fixture
def sqlite_adapter(tmp_path):
    """Provides an SQLiteAdapter using a temporary database file."""
    db_file = tmp_path / "test_koot.db"
    return SQLiteAdapter(db_path=str(db_file))

# --- Test Data ---
TEST_KEY = "chunk_001_deadbeef"
TEST_DATA = b"This is simulated encrypted binary chunk data \x00\x01\x02"

# --- Local File System Adapter Tests ---

def test_local_fs_write_and_read(local_fs_adapter):
    # Test writing
    assert local_fs_adapter.write(TEST_KEY, TEST_DATA) is True
    
    # Test reading
    retrieved_data = local_fs_adapter.read(TEST_KEY)
    assert retrieved_data == TEST_DATA

def test_local_fs_read_nonexistent(local_fs_adapter):
    assert local_fs_adapter.read("does_not_exist") is None

def test_local_fs_exists(local_fs_adapter):
    local_fs_adapter.write(TEST_KEY, TEST_DATA)
    assert local_fs_adapter.exists(TEST_KEY) is True
    assert local_fs_adapter.exists("ghost_key") is False

def test_local_fs_delete(local_fs_adapter):
    local_fs_adapter.write(TEST_KEY, TEST_DATA)
    
    # Delete existing
    assert local_fs_adapter.delete(TEST_KEY) is True
    assert local_fs_adapter.exists(TEST_KEY) is False
    
    # Delete non-existing
    assert local_fs_adapter.delete("ghost_key") is False

# --- SQLite Adapter Tests ---

def test_sqlite_write_and_read(sqlite_adapter):
    # Test writing
    assert sqlite_adapter.write(TEST_KEY, TEST_DATA) is True
    
    # Test reading
    retrieved_data = sqlite_adapter.read(TEST_KEY)
    assert retrieved_data == TEST_DATA

def test_sqlite_overwrite(sqlite_adapter):
    # Ensure writing to the same key updates the payload instead of crashing
    sqlite_adapter.write(TEST_KEY, TEST_DATA)
    new_data = b"Updated binary data"
    assert sqlite_adapter.write(TEST_KEY, new_data) is True
    assert sqlite_adapter.read(TEST_KEY) == new_data

def test_sqlite_read_nonexistent(sqlite_adapter):
    assert sqlite_adapter.read("does_not_exist") is None

def test_sqlite_exists(sqlite_adapter):
    sqlite_adapter.write(TEST_KEY, TEST_DATA)
    assert sqlite_adapter.exists(TEST_KEY) is True
    assert sqlite_adapter.exists("ghost_key") is False

def test_sqlite_delete(sqlite_adapter):
    sqlite_adapter.write(TEST_KEY, TEST_DATA)
    
    # Delete existing
    assert sqlite_adapter.delete(TEST_KEY) is True
    assert sqlite_adapter.exists(TEST_KEY) is False
    
    # Delete non-existing
    assert sqlite_adapter.delete("ghost_key") is False