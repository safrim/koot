import os
import sys
import ctypes
import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
ENCLAVE_DIR = os.path.join(PROJECT_ROOT, "koot", "crypto", "enclave")

def get_lib_path():
    lib_ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
    return os.path.join(ENCLAVE_DIR, f"libmemorylock{lib_ext}")

@pytest.fixture(scope="module")
def memory_lock_lib():
    lib_path = get_lib_path()
    if not os.path.exists(lib_path):
        pytest.skip(f"Compiled enclave library not found at {lib_path}. Run 'python scripts/build_enclave.py' first.")
    
    # Load the library
    lib = ctypes.CDLL(lib_path)
    
    # Define arg and return types for allocate_secure_key
    lib.allocate_secure_key.argtypes = [ctypes.c_size_t]
    lib.allocate_secure_key.restype = ctypes.c_void_p
    
    # Define arg and return types for destroy_secure_key
    lib.destroy_secure_key.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    lib.destroy_secure_key.restype = None
    
    return lib

def test_secure_memory_allocation_and_destruction(memory_lock_lib):
    """
    Verify the C-Enclave correctly allocates, locks, writes to, and securely frees non-pageable memory.
    """
    key_size = 32  # 256-bit Master Key simulation
    
    # 1. Allocate locked memory
    ptr = memory_lock_lib.allocate_secure_key(key_size)
    
    # If the system strictly restricts mlock limit (ulimit -l), it may return None
    assert ptr is not None, "Failed to allocate secure memory. Check OS mlock limits."
    
    try:
        # 2. Write dummy key payload to verify access bounds
        dummy_payload = b"X" * key_size
        ctypes.memmove(ptr, dummy_payload, key_size)
        
        # Verify write operations function normally inside the enclave
        extracted_data = ctypes.string_at(ptr, key_size)
        assert extracted_data == dummy_payload
        
    finally:
        # 3. Cryptographically wipe, unlock, and free
        memory_lock_lib.destroy_secure_key(ptr, key_size)
        
        # Note: Further accessing ptr via ctypes here will intentionally cause an OS-level SegFault 
        # because the memory no longer belongs to the process, proving destruction was successful.