# koot/storage/adapters/base.py
import abc
import hashlib
from typing import Optional

class StorageDriver(abc.ABC):
    """
    Abstract base class for all koot storage adapters.
    All storage backends must implement these core operations.
    """

    def __init__(self, system_salt: bytes = b"koot_default_storage_salt"):
        """
        Initializes the storage driver with a system-wide salt to prevent 
        rainbow-table attacks against tenant_id hashes.
        """
        self.system_salt = system_salt

    def derive_secure_key(self, tenant_id: str, raw_key: str) -> str:
        """
        Calculates a fast, salted BLAKE2b hash of the tenant_id.
        Prepends this cryptographic prefix to the raw_key to safely partition
        storage chunks without leaking readable metadata (e.g., 'Operative_Alpha') on disk.
        """
        # BLAKE2b is highly optimized for software and perfectly suited for fast, secure hashing
        h = hashlib.blake2b(key=self.system_salt, digest_size=16)
        h.update(tenant_id.encode('utf-8'))
        secure_prefix = h.hexdigest()
        
        return f"{secure_prefix}_{raw_key}"

    @abc.abstractmethod
    def write(self, tenant_id: str, key: str, data: bytes) -> bool:
        """Writes binary data (Envelope/Chunk) to the storage backend."""
        pass

    @abc.abstractmethod
    def read(self, tenant_id: str, key: str) -> Optional[bytes]:
        """Reads binary data from the storage backend using its key."""
        pass

    @abc.abstractmethod
    def delete(self, tenant_id: str, key: str) -> bool:
        """Deletes the specified data from the storage backend."""
        pass

    @abc.abstractmethod
    def exists(self, tenant_id: str, key: str) -> bool:
        """Checks if a given key exists in the storage backend."""
        pass