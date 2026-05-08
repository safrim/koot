# koot/identity/ledger.py
import json
import os
import threading
from koot.crypto.classical.fallback import SoftwareAESGCM

class ShadowLedger:
    """
    The Shadow Ledger Core.
    A thread-safe, dormant database defining sub-user boundaries, encrypted
    at rest using the core Master Key.
    """
    def __init__(self, db_path: str, master_key: bytes):
        self.db_path = db_path
        self.master_key = master_key
        self._lock = threading.Lock()
        
        # Initialize the database if it doesn't exist
        if not os.path.exists(self.db_path):
            self._initialize_db()
            
    def _initialize_db(self):
        with self._lock:
            if not os.path.exists(self.db_path):
                self._save_db({"tenants": {}})

    def _save_db(self, data: dict):
        """Encrypts and atomically writes the database to disk."""
        json_data = json.dumps(data).encode('utf-8')
        ciphertext, nonce = SoftwareAESGCM.encrypt(self.master_key, json_data)
        
        # Atomic write: write to a temporary file, then replace
        tmp_path = self.db_path + '.tmp'
        with open(tmp_path, 'wb') as f:
            f.write(nonce + ciphertext)
        os.replace(tmp_path, self.db_path)

    def _load_db(self) -> dict:
        """Reads and decrypts the database from disk."""
        if not os.path.exists(self.db_path):
            return {"tenants": {}}
            
        with open(self.db_path, 'rb') as f:
            file_data = f.read()
            
        if len(file_data) < 12:
            return {"tenants": {}}
            
        nonce = file_data[:12]
        ciphertext = file_data[12:]
        
        try:
            plaintext = SoftwareAESGCM.decrypt(self.master_key, nonce, ciphertext)
            return json.loads(plaintext.decode('utf-8'))
        except Exception as e:
            raise ValueError("Shadow Ledger decryption failed. Potential tampering or invalid Master Key.") from e

    def add_tenant(self, cert_hash: str, tenant_id: str, permissions: list, escrowed_key: str):
        """Safely registers a new sub-user into the ledger."""
        with self._lock:
            db = self._load_db()
            db["tenants"][cert_hash] = {
                "tenant_id": tenant_id,
                "permissions": permissions,
                "escrowed_key": escrowed_key,
                "locked": False
            }
            self._save_db(db)

    def get_tenant(self, cert_hash: str) -> dict:
        """Retrieves tenant details by their certificate hash."""
        with self._lock:
            db = self._load_db()
            return db["tenants"].get(cert_hash)

    def update_tenant_status(self, cert_hash: str, locked: bool):
        """Locks or unlocks a sub-user partition."""
        with self._lock:
            db = self._load_db()
            if cert_hash in db["tenants"]:
                db["tenants"][cert_hash]["locked"] = locked
                self._save_db(db)
            else:
                raise KeyError(f"Tenant with cert hash '{cert_hash}' not found in Ledger.")