# koot/storage/adapters/local_fs.py
import os
from pathlib import Path
from typing import Optional
from .base import StorageDriver

class LocalFileSystemAdapter(StorageDriver):
    """
    Storage adapter for the local OS file system.
    """
    def __init__(self, base_directory: str, system_salt: bytes = b"koot_default_storage_salt"):
        # Initialize the base class with the system salt
        super().__init__(system_salt=system_salt)
        self.base_dir = Path(base_directory)
        # Ensure the storage directory exists
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, secure_key: str) -> Path:
        # Prevent directory traversal attacks
        safe_key = os.path.basename(secure_key)
        return self.base_dir / safe_key

    def write(self, tenant_id: str, key: str, data: bytes) -> bool:
        secure_key = self.derive_secure_key(tenant_id, key)
        try:
            target_path = self._get_path(secure_key)
            with open(target_path, 'wb') as f:
                f.write(data)
            return True
        except IOError:
            return False

    def read(self, tenant_id: str, key: str) -> Optional[bytes]:
        secure_key = self.derive_secure_key(tenant_id, key)
        target_path = self._get_path(secure_key)
        if not target_path.exists():
            return None
        try:
            with open(target_path, 'rb') as f:
                return f.read()
        except IOError:
            return None

    def delete(self, tenant_id: str, key: str) -> bool:
        secure_key = self.derive_secure_key(tenant_id, key)
        target_path = self._get_path(secure_key)
        if target_path.exists():
            try:
                target_path.unlink()
                return True
            except OSError:
                return False
        return False

    def exists(self, tenant_id: str, key: str) -> bool:
        secure_key = self.derive_secure_key(tenant_id, key)
        return self._get_path(secure_key).exists()