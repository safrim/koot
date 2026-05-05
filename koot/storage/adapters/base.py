# koot/storage/adapters/base.py
import abc
from typing import Optional

class StorageDriver(abc.ABC):
    """
    Abstract base class for all koot storage adapters.
    All storage backends must implement these core operations.
    """

    @abc.abstractmethod
    def write(self, key: str, data: bytes) -> bool:
        """Writes binary data (Envelope/Chunk) to the storage backend."""
        pass

    @abc.abstractmethod
    def read(self, key: str) -> Optional[bytes]:
        """Reads binary data from the storage backend using its key."""
        pass

    @abc.abstractmethod
    def delete(self, key: str) -> bool:
        """Deletes the specified data from the storage backend."""
        pass

    @abc.abstractmethod
    def exists(self, key: str) -> bool:
        """Checks if a given key exists in the storage backend."""
        pass