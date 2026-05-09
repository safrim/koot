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
    def __init__(self, db_path: str, master_key: bytes, is_duress_mode: bool = False):
        self.is_duress_mode = is_duress_mode
        self.master_key = master_key
        self._lock = threading.Lock()
        
        # --- Engineered Countermeasure: Dummy Routing ---
        if self.is_duress_mode:
            base, ext = os.path.splitext(db_path)
            self.db_path = f"{base}_dummy{ext}"
        else:
            self.db_path = db_path
        
        if not os.path.exists(self.db_path):
            self._initialize_db()
            
    def _initialize_db(self):
        with self._lock:
            if not os.path.exists(self.db_path):
                self._save_db({"tenants": {}})

    def _save_db(self, data: dict):
        json_data = json.dumps(data).encode('utf-8')
        ciphertext, nonce = SoftwareAESGCM.encrypt(self.master_key, json_data)
        
        tmp_path = self.db_path + '.tmp'
        with open(tmp_path, 'wb') as f:
            f.write(nonce + ciphertext)
        os.replace(tmp_path, self.db_path)

    def _load_db(self) -> dict:
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
        with self._lock:
            db = self._load_db()
            return db["tenants"].get(cert_hash)

    def update_tenant_status(self, cert_hash: str, locked: bool):
        with self._lock:
            db = self._load_db()
            if cert_hash in db["tenants"]:
                db["tenants"][cert_hash]["locked"] = locked
                self._save_db(db)
            else:
                raise KeyError(f"Tenant with cert hash '{cert_hash}' not found in Ledger.")

    def lock_tenant_by_id(self, tenant_id: str) -> bool:
        with self._lock:
            db = self._load_db()
            for cert_hash, data in db["tenants"].items():
                if data.get("tenant_id") == tenant_id:
                    data["locked"] = True
                    self._save_db(db)
                    return True
            return False

    def shred(self):
        """
        Countermeasure D (Terminal Nuke): Instantly overwrites the database and 
        temporary files with random noise before deleting them to prevent 
        forensic recovery from the hard drive.
        """
        with self._lock:
            for target in [self.db_path, self.db_path + '.tmp']:
                if os.path.exists(target):
                    try:
                        size = os.path.getsize(target)
                        # Overwrite with cryptographically secure random bytes
                        with open(target, 'r+b') as f:
                            f.write(os.urandom(size))
                        os.remove(target)
                    except Exception:
                        pass # Best effort destruction during a nuke scenario