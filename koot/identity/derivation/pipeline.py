import os
import gc
import sys
import ctypes
import argon2.low_level
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from typing import Optional
from koot.core.bus.environment import EnvironmentSensor
from koot.crypto.classical.fallback import SoftwareAESGCM

# --- C-Enclave FFI Binding ---
ENCLAVE_AVAILABLE = False
try:
    _lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../crypto/enclave/libmemorylock.so'))
    _enclave_lib = ctypes.CDLL(_lib_path)
    _enclave_lib.allocate_secure_key.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    _enclave_lib.allocate_secure_key.restype = ctypes.c_int
    _enclave_lib.destroy_secure_key.argtypes = [ctypes.c_int]
    _enclave_lib.destroy_secure_key.restype = None
    ENCLAVE_AVAILABLE = True
except OSError:
    import logging
    logging.warning("C-Enclave shared library not found. Have you run scripts/build_enclave.py?")


class EntropyPipeline:
    def __init__(self, sensor: EnvironmentSensor = None, force_scaling_override: dict = None):
        self.sensor = sensor or EnvironmentSensor()
        self.capabilities = self.sensor.get_telemetry()
        
        self.time_cost = 3
        self.hash_len = 32  # 256-bit output key
        self.active_key_id: Optional[int] = None
        
        # Duress & Nuke Protocol State
        self.duress_hash: Optional[str] = None
        self.is_duress_mode: bool = False
        
        self.terminal_hash: Optional[str] = None
        self.nuke_callbacks = []
        
        ram_gb = self.capabilities.get("ram_gb", 4.0)
        
        if force_scaling_override:
            self.memory_cost = force_scaling_override.get("memory_cost", 262144)
            self.parallelism = force_scaling_override.get("parallelism", 4)
        elif ram_gb <= 2.0:
            self.memory_cost = 65536
            self.parallelism = 2
        elif ram_gb <= 8.0:
            self.memory_cost = 262144
            self.parallelism = 4
        else:
            self.memory_cost = 524288
            self.parallelism = 8

    def set_duress_hash(self, hashed_duress_pwd: str):
        """Registers the Argon2 hash of the duress password."""
        self.duress_hash = hashed_duress_pwd

    def set_terminal_hash(self, hashed_terminal_pwd: str):
        """Registers the Argon2 hash of the Terminal (Nuke) password."""
        self.terminal_hash = hashed_terminal_pwd

    def register_nuke_callback(self, callback):
        """Registers system callbacks (e.g., ledger.shred) to execute on Terminal Key."""
        self.nuke_callbacks.append(callback)

    def derive_key(self, secret: str, salt: bytes) -> tuple[bytes, bytes]:
        """
        Standard Argon2id derivation that returns raw bytes.
        Used for intermediate keys or internal factors that don't need C-Enclave locking.
        """
        secret_bytes = secret.encode('utf-8')
        try:
            raw_key = argon2.low_level.hash_secret_raw(
                secret=secret_bytes,
                salt=salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=self.hash_len,
                type=argon2.low_level.Type.ID 
            )
            return raw_key, salt
        finally:
            if 'raw_key' in locals():
                del raw_key
            del secret_bytes
            gc.collect()

    def derive_and_lock_key(self, secret: str, salt: bytes = None, hardware_factor: bytes = None) -> tuple[int, bytes]:
        # --- PASTE THIS DEBUG BLOCK ---
        print("\n====== [CRYPTOGRAPHY DEBUG] ======")
        print(f"Password Length : {len(secret) if secret else 0}")
        print(f"Salt            : {salt.hex() if salt else 'CRITICAL WARNING: NO SALT PROVIDED'}")
        print(f"Hardware Factor : {hardware_factor.hex() if hardware_factor else 'NONE'}")
        print("==================================\n")
        # ------------------------------
        """
        Derives the Master Key using Argon2id and locks it in the C-Enclave.
        Now supports an optional hardware_factor (TPM signature) for AppRole security.
        """
        # --- Engineered Countermeasure: Terminal Nuke Key ---
        if self.terminal_hash:
            try:
                ph = PasswordHasher()
                if ph.verify(self.terminal_hash, secret):
                    for cb in self.nuke_callbacks:
                        try:
                            cb()
                        except Exception:
                            pass
                    self.go_cold() 
                    sys.exit(86)
            except VerifyMismatchError:
                pass 

        if not ENCLAVE_AVAILABLE:
            raise RuntimeError("CRITICAL: C-Enclave memory lockdown is unavailable. Vault access denied.")

        if not salt:
            salt = os.urandom(16)
            
        self.is_duress_mode = False
        if self.duress_hash:
            try:
                ph = PasswordHasher()
                if ph.verify(self.duress_hash, secret):
                    self.is_duress_mode = True
            except VerifyMismatchError:
                pass 
        
        # --- AppRole: Combine Password + Hardware Factor ---
        # We append the hardware factor bytes to the secret bytes for a unified salt-resistant secret
        composite_secret = secret.encode('utf-8') + (hardware_factor or b"")
            
        try:
            raw_key = argon2.low_level.hash_secret_raw(
                secret=composite_secret,
                salt=salt,
                time_cost=self.time_cost,
                memory_cost=self.memory_cost,
                parallelism=self.parallelism,
                hash_len=self.hash_len,
                type=argon2.low_level.Type.ID 
            )
            
            self.active_key_id = _enclave_lib.allocate_secure_key(raw_key, len(raw_key))
            return self.active_key_id, salt
            
        finally:
            if 'raw_key' in locals():
                del raw_key
            del composite_secret
            # Manual cleanup of strings/bytes to minimize RAM traces
            gc.collect() 

    def go_cold(self):
        """Safely destructs the master key and frees C-Enclave secure memory."""
        if ENCLAVE_AVAILABLE and self.active_key_id is not None:
            _enclave_lib.destroy_secure_key(self.active_key_id)
            self.active_key_id = None
            gc.collect()

    def wrap_for_escrow(self, tenant_key: bytes, core_master_key: bytes) -> str:
        """Cryptographically wraps a tenant key with the core master key."""
        ciphertext, nonce = SoftwareAESGCM.encrypt(core_master_key, tenant_key)
        return (nonce + ciphertext).hex()

    def unwrap_from_escrow(self, escrowed_hex: str, core_master_key: bytes) -> bytes:
        """Unwraps a tenant key stored in escrow using the core master key."""
        try:
            data = bytes.fromhex(escrowed_hex)
            if len(data) < 12:
                raise ValueError("Escrowed data is too short for a valid nonce.")
            nonce = data[:12]
            ciphertext = data[12:]
            return SoftwareAESGCM.decrypt(core_master_key, nonce, ciphertext)
        except Exception as e:
            raise ValueError("Escrow decryption failed.") from e