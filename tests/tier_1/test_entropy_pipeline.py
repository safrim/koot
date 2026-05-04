import unittest
from koot.identity.derivation.pipeline import EntropyPipeline

# FIX: Update the mock sensors to match the get_telemetry interface
class MockLowRamSensor:
    def get_telemetry(self):
        return {"ram_gb": 1.0} # Simulate 1 GB RAM

class MockHighRamSensor:
    def get_telemetry(self):
        return {"ram_gb": 32.0} # Simulate 32 GB RAM

class TestEntropyPipeline(unittest.TestCase):
    # ... (keep all the test functions exactly as they are) ...
    def test_hardware_aware_scaling(self):
        """Proves the pipeline scales Argon2id memory costs based on available RAM."""
        # Test Low RAM IoT Scenario
        low_ram_pipeline = EntropyPipeline(sensor=MockLowRamSensor())
        self.assertEqual(low_ram_pipeline.memory_cost, 65536)
        self.assertEqual(low_ram_pipeline.parallelism, 2)
        
        # Test High RAM Server Scenario
        high_ram_pipeline = EntropyPipeline(sensor=MockHighRamSensor())
        self.assertEqual(high_ram_pipeline.memory_cost, 524288)
        self.assertEqual(high_ram_pipeline.parallelism, 8)

    def test_key_derivation_determinism(self):
        """Proves that a key can be reliably reconstructed using the same salt."""
        pipeline = EntropyPipeline()
        password = "ZeroTrustMasterPassword123!"
        
        # Generate initially (creates a new salt)
        key1, salt = pipeline.derive_key(password)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(salt), 16)
        
        # Derive again by providing the generated salt
        key2, _ = pipeline.derive_key(password, salt)
        
        # The cryptographic keys must match exactly
        self.assertEqual(key1, key2)

if __name__ == '__main__':
    unittest.main()