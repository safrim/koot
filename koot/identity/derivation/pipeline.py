import os
import gc
import argon2.low_level
from koot.core.bus.environment import EnvironmentSensor
from koot.crypto.classical.fallback import SoftwareAESGCM

class EntropyPipeline:
    def __init__(self, sensor: EnvironmentSensor = None, force_scaling_override: dict = None):
        # Connect to the central nervous system to probe the hardware
        self.sensor = sensor or EnvironmentSensor()
        
        # Call the correct method we built in Phase 1.2
        self.capabilities = self.sensor.get_telemetry()
        
        # Base Argon2id parameters
        self.time_cost = 3
        self.hash_len = 32  # 256-bit output key for AES-256 / Kyber
        
        # Read ram_gb directly from the telemetry dictionary
        ram_gb = self.capabilities.get("ram_gb", 4.0)
        
        if force_scaling_override:
            self.memory_cost = force_scaling_override.get("memory_cost", 262144)
            self.parallelism = force_scaling_override.get("parallelism", 4)
        elif ram_gb <= 2.0:
            # IoT / Edge Device: Fallback to 64MB, 2 threads
            self.memory_cost = 65536
            self.parallelism = 2
        elif ram_gb <= 8.0:
            # Standard PC: 256MB, 4 threads
            self.memory_cost = 262144
            self.parallelism = 4
        else:
            # High-End Workstation / Server: 512MB, 8 threads
            self.memory_cost = 524288
            self.parallelism = 8

    def derive_key(self, secret: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derives a 32-byte raw cryptographic key from a secret string.
        Returns a tuple of (raw_key_bytes, salt_bytes).
        """
        if not salt:
            # Generate a cryptographically secure 16-byte salt if one isn't provided
            salt = os.urandom(16)
            
        secret_bytes = secret.encode('utf-8')
            
        try:
            # We use low_level.hash_secret_raw to get the raw 32 bytes needed for cryptography
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
            # --- Engineered Countermeasure: Ephemeral Memory Handling ---
            del secret_bytes
            del secret
            gc.collect()

    def generate_tenant_master_key(self) -> bytes:
        """
        Generates a true mathematically random 256-bit (32-byte) key for a sub-tenant.
        This ensures cryptographic isolation without deriving keys from public mTLS certificates.
        """
        return os.urandom(32)

    def wrap_for_escrow(self, tenant_key: bytes, core_master_key: bytes) -> str:
        """
        [Phase 2 - Escrow Protocol]
        Encrypts a tenant's master key using the core Master Key.
        Returns a hex-encoded string of (nonce + ciphertext) safe for the Shadow Ledger.
        """
        ciphertext, nonce = SoftwareAESGCM.encrypt(core_master_key, tenant_key)
        return (nonce + ciphertext).hex()

    def unwrap_from_escrow(self, escrowed_hex: str, core_master_key: bytes) -> bytes:
        """
        [Phase 2 - Escrow Protocol]
        Decrypts an escrowed hex string back into the raw tenant master key, 
        provided the core Master Key is correct.
        """
        try:
            data = bytes.fromhex(escrowed_hex)
            if len(data) < 12:
                raise ValueError("Escrowed data is too short to contain a valid nonce.")
                
            nonce = data[:12]
            ciphertext = data[12:]
            
            tenant_key = SoftwareAESGCM.decrypt(core_master_key, nonce, ciphertext)
            return tenant_key
        except Exception as e:
            raise ValueError("Escrow decryption failed. Invalid Master Key or tampered payload.") from e