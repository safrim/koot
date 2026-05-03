import unittest
import time
from koot.core.bus.environment import EnvironmentSensor
from koot.core.bus.registry import AdaptiveRegistry

# --- DUMMY PLUGIN FOR IPC TESTING ---
class MockCryptoPlugin:
    """A fake plugin to test the IPC pipe and crash isolation."""
    @staticmethod
    def encrypt(text: str):
        return f"ENCRYPTED_{text}"
        
    @staticmethod
    def trigger_fatal_crash():
        # This simulates a segfault or malicious memory leak
        raise RuntimeError("FATAL CORE PANIC!")

class TestBusIntegration(unittest.TestCase):

    def test_real_environment_telemetry(self):
        """Verifies the sensor outputs the strict capability matrix using real hardware."""
        sensor = EnvironmentSensor()
        telemetry = sensor.get_telemetry()
        
        self.assertIn("os", telemetry)
        self.assertIn("tier", telemetry)
        self.assertIn("hardware_accel", telemetry)
        self.assertIn("aes_ni", telemetry["hardware_accel"])
        self.assertIn("tpm_present", telemetry["hardware_accel"])
        self.assertIn("system_health", telemetry)

    def test_ipc_dispatch_success(self):
        """Verifies the main system can talk to the isolated plugin process."""
        registry = AdaptiveRegistry()
        registry.mount_plugin("mock_crypto", MockCryptoPlugin)
        
        # Give the OS a tiny fraction of a second to spawn the background process
        time.sleep(0.1)
        
        result = registry.dispatch("mock_crypto", "encrypt", text="top_secret_data")
        self.assertEqual(result, "ENCRYPTED_top_secret_data")

    def test_strict_process_isolation_crash(self):
        """
        COUNTERMEASURE TEST: 
        Verifies that a catastrophic plugin crash does not kill the main Registry.
        """
        registry = AdaptiveRegistry()
        registry.mount_plugin("crashing_plugin", MockCryptoPlugin)
        time.sleep(0.1)
        
        # We expect the dispatch to raise an Exception because the child process died,
        # but the main Test runner (the 'Kernel') should survive to catch it.
        with self.assertRaises(Exception) as context:
            registry.dispatch("crashing_plugin", "trigger_fatal_crash")
            
        # Verify the error passed through the pipe was exactly what we simulated
        self.assertTrue("FATAL CORE PANIC" in str(context.exception))

if __name__ == '__main__':
    unittest.main(verbosity=2)