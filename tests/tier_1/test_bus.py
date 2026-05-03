from koot.core.bus.environment import EnvironmentSensor
from koot.core.bus.registry import PluginRegistry

class QuantumCryptoPlugin:
    def encrypt(self, data: bytes) -> bytes:
        return b"Kyber_Encrypted_" + data
    def decrypt(self, data: bytes) -> bytes:
        return data

class FallbackCryptoPlugin:
    def apply_hardware_limits(self, profile: dict):
        self.chunk_size = profile.get("chunking_engine_max_kb", 16)
        
    def encrypt(self, data: bytes) -> bytes:
        return b"AES_Encrypted_" + data[:self.chunk_size]
    def decrypt(self, data: bytes) -> bytes:
        return data

def test_registry_bus():
    print("[*] Initializing Phase 1.2 Test: Advanced Environment Sensor & Strict Bus\n")
    
    # 1. Sense Environment
    sensor = EnvironmentSensor()
    metrics = sensor.probe_system()
    profile = metrics["security_enforcement_profile"]
    print(f"[+] Computed Hardware Tier: {profile['hardware_tier']}")
    print(f"[+] PQC Permitted: {profile['permit_hybrid_pqc']}\n")

    # Override profile to simulate a weak IoT device for testing
    print("[!] Simulating drop to Constrained IoT Device...")
    profile["permit_hybrid_pqc"] = False
    profile["chunking_engine_max_kb"] = 16
    
    # 2. Initialize Bus with strict profile
    bus = PluginRegistry(system_profile=profile)
    
    # 3. Attempt to load heavy Quantum Crypto
    print("\n    -> Attempting to mount heavy 'QuantumCrypto'...")
    bus.mount_plugin(
        name="QuantumCrypto", 
        plugin_class=QuantumCryptoPlugin, 
        required_methods=["encrypt", "decrypt"],
        requires_pqc=True # This should trigger the rejection
    )
    
    # 4. Attempt to load Lightweight Fallback
    print("\n    -> Attempting to mount lightweight 'FallbackCrypto'...")
    bus.mount_plugin(
        name="FallbackCrypto", 
        plugin_class=FallbackCryptoPlugin, 
        required_methods=["encrypt", "decrypt"],
        requires_pqc=False
    )
    
    # 5. Execute through the Sandbox Wrapper
    print("\n[+] Executing Payload through Sandbox...")
    crypto = bus.get_plugin_interface("FallbackCrypto")
    test_str = b"Agnostic Payload"
    
    # Use keyword args explicitly for the sandbox
    encrypted = crypto.execute("encrypt", data=test_str)
    print(f"    Result: {encrypted}")

    print("\n[SUCCESS] Bus correctly rejected heavy plugins and safely executed fallbacks.")

if __name__ == "__main__":
    test_registry_bus()