import os
import sys
import ctypes
import atexit

class SecureMemoryException(Exception):
    pass

class EnclaveManager:
    """
    Python FFI boundary for the C-Enclave. 
    Handles loading the OS-locked library and managing secure memory pointers.
    """
    def __init__(self):
        self.lib = self._load_library()
        
        # Define C arg/return types strictly to prevent memory corruption
        self.lib.allocate_secure_key.argtypes = [ctypes.c_size_t]
        self.lib.allocate_secure_key.restype = ctypes.c_void_p
        self.lib.destroy_secure_key.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        self.lib.destroy_secure_key.restype = None

    def _load_library(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        lib_ext = ".dll" if sys.platform == "win32" else ".dylib" if sys.platform == "darwin" else ".so"
        lib_path = os.path.join(base_dir, f"libmemorylock{lib_ext}")
        
        if not os.path.exists(lib_path):
            raise SecureMemoryException(f"C-Enclave not compiled. Missing: {lib_path}")
        
        return ctypes.CDLL(lib_path)

    def allocate(self, payload: bytes) -> tuple:
        """
        Allocates locked memory and writes the payload into it.
        Returns: (pointer_address, size)
        """
        size = len(payload)
        ptr = self.lib.allocate_secure_key(size)
        if not ptr:
            raise SecureMemoryException("OS denied locked memory allocation (check mlock limits).")
        
        # Move the payload bytes into the secure C memory
        ctypes.memmove(ptr, payload, size)
        return ptr, size

    def read(self, ptr: int, size: int) -> bytes:
        """Extracts the data back into Python's memory temporarily."""
        if not ptr or size <= 0:
            return b""
        return ctypes.string_at(ptr, size)

    def destroy(self, ptr: int, size: int):
        """Cryptographically wipes and unlocks the memory."""
        if ptr and size > 0:
            self.lib.destroy_secure_key(ptr, size)