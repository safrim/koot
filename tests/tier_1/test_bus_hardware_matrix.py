import unittest
from unittest.mock import patch
from koot.core.bus.registry import AdaptiveRegistry

class TestHardwareMatrix(unittest.TestCase):

    def setUp(self):
        # Base fake telemetry that we will modify per test
        self.base_telemetry = {
            "os": "Linux",
            "tier": "ENTERPRISE",
            "ram_gb": 16.0,
            "cpu_cores": 8,
            "hardware_accel": {"aes_ni": True, "tpm_present": True},
            "system_health": {"thermal_load": "NORMAL", "entropy_healthy": True}
        }

    @patch('koot.core.bus.environment.EnvironmentSensor.get_telemetry')
    def test_enterprise_beast_routing(self, mock_telemetry):
        """SCENARIO A: High-End Server. Should route to fast hardware."""
        mock_telemetry.return_value = self.base_telemetry
        
        registry = AdaptiveRegistry()
        self.assertEqual(registry.resolve_capability("crypto"), "crypto.accelerated")
        self.assertEqual(registry.resolve_capability("streaming"), "stream.max_throughput")

    @patch('koot.core.bus.environment.EnvironmentSensor.get_telemetry')
    def test_weak_iot_routing(self, mock_telemetry):
        """SCENARIO B: Weak IoT Device (No AES-NI, Low RAM). Should route to safe fallbacks."""
        iot_telemetry = self.base_telemetry.copy()
        iot_telemetry["tier"] = "IOT_EDGE"
        iot_telemetry["hardware_accel"]["aes_ni"] = False
        mock_telemetry.return_value = iot_telemetry
        
        registry = AdaptiveRegistry()
        self.assertEqual(registry.resolve_capability("crypto"), "crypto.fallback")

    @patch('koot.core.bus.environment.EnvironmentSensor.get_telemetry')
    def test_thermal_meltdown_routing(self, mock_telemetry):
        """SCENARIO C: Server is overheating. Should throttle data streaming."""
        hot_telemetry = self.base_telemetry.copy()
        hot_telemetry["system_health"]["thermal_load"] = "CRITICAL_HEAT"
        mock_telemetry.return_value = hot_telemetry
        
        registry = AdaptiveRegistry()
        self.assertEqual(registry.resolve_capability("streaming"), "stream.throttled")

    @patch('koot.core.bus.environment.EnvironmentSensor.get_telemetry')
    def test_admin_override_routing(self, mock_telemetry):
        """SCENARIO D: Admin forces software crypto, even on Enterprise hardware."""
        mock_telemetry.return_value = self.base_telemetry
        
        # We pass the override matrix during boot
        registry = AdaptiveRegistry(override_matrix={"force_software_crypto": True})
        
        # Even though AES-NI is True in the mock, the override must win
        self.assertEqual(registry.resolve_capability("crypto"), "crypto.fallback")

if __name__ == '__main__':
    unittest.main(verbosity=2)