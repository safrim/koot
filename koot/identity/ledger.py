# koot/identity/ledger.py
import json
import os
import threading
import logging
from koot.crypto.classical.fallback import SoftwareAESGCM

class ShadowLedger:
    """
    The Shadow Ledger Core.
    A thread-safe, stateful database defining sub-user boundaries, 
    encrypted at rest using the core Master Key derived from Password + TPM.
    """
    def __init__(self, db_path: str, master_key: bytes, is_duress_mode: bool = False):
        self.is_duress_mode = is_duress_mode
        self.master_key = master_key
        self.logger = logging.getLogger("koot.identity.ledger")
        
        # We use RLock (Reentrant Lock) so that locked methods can call 
        # other locked methods in the same thread without deadlocking.
        self._lock = threading.RLock()
        
        # --- Engineered Countermeasure: Dummy Routing ---
        # If the system is unlocked with a Duress Password, we transparently
        # redirect all writes to a 'dummy' file to protect the real data.
        if self.is_duress_mode:
            base, ext = os.path.splitext(db_path)
            self.db_path = f"{base}_dummy{ext}"
            self.logger.warning("DURESS MODE ACTIVE: Routing to decoy ledger.")
        else:
            self.db_path = db_path
        
        # Standardized attribute for decrypted data (Fixes the IPC Server Error)
        self.db = {"tenants": {}, "secrets": {}}
        
        # Load existing data into RAM immediately upon initialization
        if os.path.exists(self.db_path):
            self._load_db()
        else:
            self._initialize_db()

    def _initialize_db(self):
        """Creates the initial encrypted birth-file on disk."""
        with self._lock:
            if not os.path.exists(self.db_path):
                self.db = {"tenants": {}, "secrets": {}}
                self._save_db()
                self.logger.info(f"Initialized new ledger at {self.db_path}")

    def _save_db(self):
        """
        Serializes the RAM state (self.db) and seals it to disk.
        Uses an atomic 'replace' to prevent file corruption during power loss.
        """
        with self._lock:
            try:
                # 1. Agnostic serialization
                json_data = json.dumps(self.db).encode('utf-8')
                
                # 2. Encrypt using AES-GCM (Master Key in RAM)
                # Note: This assumes your SoftwareAESGCM.encrypt returns (ciphertext, nonce)
                ciphertext, nonce = SoftwareAESGCM.encrypt(self.master_key, json_data)
                
                # 3. Atomic Write
                tmp_path = self.db_path + '.tmp'
                with open(tmp_path, 'wb') as f:
                    f.write(nonce + ciphertext)
                os.replace(tmp_path, self.db_path)
                
            except Exception as e:
                self.logger.error(f"Persistence failure: {e}")
                raise RuntimeError(f"Shadow Ledger could not be sealed: {e}")

    def _load_db(self) -> dict:
        """
        Decrypts the physical shadow file and loads it into self.db.
        Returns the data for convenience.
        """
        with self._lock:
            if not os.path.exists(self.db_path):
                return self.db

            try:
                with open(self.db_path, 'rb') as f:
                    file_data = f.read()
                
                if len(file_data) < 12:
                    return self.db

                # Koot Standard: First 12 bytes are the AES-GCM Nonce
                nonce = file_data[:12]
                ciphertext = file_data[12:]

                # High-Stakes Decryption
                plaintext = SoftwareAESGCM.decrypt(self.master_key, nonce, ciphertext)
                
                # Update RAM state
                self.db = json.loads(plaintext.decode('utf-8'))
                return self.db
                
            except Exception as e:
                self.logger.critical("INTEGRITY ERROR: Ledger decryption failed.")
                raise ValueError("Shadow Ledger decryption failed. Potential tampering or invalid Master Key.") from e

    # --- Multi-Tenant Management Methods ---

    def add_tenant(self, cert_hash: str, tenant_id: str, permissions: list, escrowed_key: str):
        """Adds an authorized operative (tenant) to the ledger."""
        with self._lock:
            self.db["tenants"][cert_hash] = {
                "tenant_id": tenant_id,
                "permissions": permissions,
                "escrowed_key": escrowed_key,
                "locked": False,
                "secrets": {}
            }
            self._save_db()

    def get_tenant(self, cert_hash: str) -> dict:
        """Retrieves operative metadata by their certificate fingerprint."""
        with self._lock:
            return self.db["tenants"].get(cert_hash)

    def update_tenant_status(self, cert_hash: str, locked: bool):
        """Temporarily freezes or unfreezes an operative's access."""
        with self._lock:
            if cert_hash in self.db["tenants"]:
                self.db["tenants"][cert_hash]["locked"] = locked
                self._save_db()
            else:
                raise KeyError(f"Tenant '{cert_hash}' not found.")

    def lock_tenant_by_id(self, tenant_id: str) -> bool:
        with self._lock:
            db = self._load_db()
            for cert_hash, data in db["tenants"].items():
                if data.get("tenant_id") == tenant_id:
                    data["locked"] = True
                    self._save_db(db)
                    return True
            return False

    # --- Secret Storage & Indexing ---

    def set(self, key: str, value: any):
        """
        General-purpose secret storage.
        Encrypts a value and binds it to a key in the root ledger.
        """
        with self._lock:
            if "secrets" not in self.db:
                self.db["secrets"] = {}
            self.db["secrets"][key] = value
            self._save_db()

    def get(self, key: str) -> any:
        """Retrieves a secret from the decrypted RAM map."""
        with self._lock:
            return self.db.get("secrets", {}).get(key)
    
    def delete(self, key: str):
        """
        Purges a secret from the decrypted RAM map and seals the change to disk.
        """
        with self._lock:
            # Check if the secrets dictionary exists and contains the key
            if "secrets" in self.db and key in self.db["secrets"]:
                del self.db["secrets"][key]
                self._save_db() # Immediately encrypts and overwrites the disk
                return True
            return False

    def update_index(self, tenant_id: str, secret_key: str, manifest: list):
        """Records the chunk map for a specific secret inside a tenant's context."""
        with self._lock:
            target_key = None
            for key, data in self.db["tenants"].items():
                if data.get("tenant_id") == tenant_id:
                    target_key = key
                    break
            
            if target_key is None:
                target_key = tenant_id # Fallback for testing
                if target_key not in self.db["tenants"]:
                    self.db["tenants"][target_key] = {"tenant_id": tenant_id, "secrets": {}}

            if "secrets" not in self.db["tenants"][target_key]:
                self.db["tenants"][target_key]["secrets"] = {}
                
            self.db["tenants"][target_key]["secrets"][secret_key] = manifest
            self._save_db()

    def get_index(self, tenant_id: str, secret_key: str) -> list:
        """Retrieves chunk manifest for a secret from a tenant context."""
        with self._lock:
            for data in self.db["tenants"].values():
                if data.get("tenant_id") == tenant_id:
                    return data.get("secrets", {}).get(secret_key)
            return None

    # --- System Defense ---

    def shred(self):
        """
        Countermeasure D (Terminal Nuke): Instantly overwrites the database 
        with random noise before deletion to defeat forensic disk recovery.
        """
        with self._lock:
            for target in [self.db_path, self.db_path + '.tmp']:
                if os.path.exists(target):
                    try:
                        size = os.path.getsize(target)
                        with open(target, 'r+b') as f:
                            f.write(os.urandom(size))
                        os.remove(target)
                    except Exception:
                        pass # Best effort destruction
            self.db = {}