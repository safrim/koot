# koot/storage/adapters/local_fs.py
import os
from pathlib import Path
from typing import Optional
from .base import StorageDriver

class LocalFileSystemAdapter(StorageDriver):
    """
    Storage adapter for the local OS file system.
    """
    def __init__(self, base_directory: str):
        self.base_dir = Path(base_directory)
        # Ensure the storage directory exists
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, key: str) -> Path:
        # Prevent directory traversal attacks
        safe_key = os.path.basename(key)
        return self.base_dir / safe_key

    def write(self, key: str, data: bytes) -> bool:
        try:
            target_path = self._get_path(key)
            with open(target_path, 'wb') as f:
                f.write(data)
            return True
        except IOError:
            return False

    def read(self, key: str) -> Optional[bytes]:
        target_path = self._get_path(key)
        if not target_path.exists():
            return None
        try:
            with open(target_path, 'rb') as f:
                return f.read()
        except IOError:
            return None

    def delete(self, key: str) -> bool:
        target_path = self._get_path(key)
        if target_path.exists():
            try:
                target_path.unlink()
                return True
            except OSError:
                return False
        return False

    def exists(self, key: str) -> bool:
        return self._get_path(key).exists()