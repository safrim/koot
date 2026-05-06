# tests/tier_1/test_breach_radar.py
import pytest
import os
from koot.plugins.breach_radar import BreachRadarPlugin
from koot.core.bus.contracts import ContractEnforcer

class MockEnvironmentSensor:
    """Simulates hardware capabilities for the Adaptive Registry Bus."""
    def __init__(self, ram_mb=1024, disk_mb=10000):
        self.ram = ram_mb
        self.disk = disk_mb

    def get_available_ram_mb(self):
        return self.ram

    def get_available_disk_mb(self):
        return self.disk

def test_breach_radar_contract_compliance():
    """Ensure the plugin satisfies the Tier 1 Interface requirements."""
    sensor = MockEnvironmentSensor()
    radar = BreachRadarPlugin(sensor, is_enabled=False)
    
    # Required capabilities for the Registry Bus
    required_methods = ['is_compromised', 'ingest_compromised_password', 'check_capabilities']
    assert ContractEnforcer.verify_tier_1(radar, required_methods) is True

def test_breach_radar_dormant_by_default():
    """Verify the plugin remains dormant and 'fails safe' if not explicitly enabled."""
    sensor = MockEnvironmentSensor()
    radar = BreachRadarPlugin(sensor, is_enabled=False)
    
    assert radar.is_enabled is False
    assert radar.dataset_type == "dormant"
    # Should not flag anything while dormant
    assert radar.is_compromised("password123") is False

def test_breach_radar_hardware_scaling():
    """Test that koot dynamically selects the dataset based on hardware profile."""
    # Scenario 1: High disk availability -> HIBP Mode (mmap)
    high_spec = MockEnvironmentSensor(ram_mb=8000, disk_mb=20000)
    radar_high = BreachRadarPlugin(high_spec, is_enabled=True, filepath="test_hibp.bin")
    assert radar_high.dataset_type == "hibp_1_billion"
    radar_high.close()
    if os.path.exists("test_hibp.bin"): os.remove("test_hibp.bin")

    # Scenario 2: Low disk but enough RAM -> RockYou Mode (RAM)
    low_disk = MockEnvironmentSensor(ram_mb=1024, disk_mb=100)
    radar_low = BreachRadarPlugin(low_disk, is_enabled=True)
    assert radar_low.dataset_type == "rockyou_10_million"
    radar_low.close()

def test_breach_radar_mmap_persistence():
    """Verify that ingested passwords survive system reboots (disk persistence)."""
    sensor = MockEnvironmentSensor(disk_mb=10000)
    test_path = "persistence_test.bin"
    
    # 1. First Session: Ingest data and close
    radar = BreachRadarPlugin(sensor, is_enabled=True, filepath=test_path)
    radar.ingest_compromised_password("breached_secret_2026")
    assert radar.is_compromised("breached_secret_2026") is True
    radar.close() # Triggers mmap.flush()
    
    # 2. Second Session: Re-open the same file
    radar_new = BreachRadarPlugin(sensor, is_enabled=True, filepath=test_path)
    # Data must be mathematically present in the bit array on disk
    assert radar_new.is_compromised("breached_secret_2026") is True
    radar_new.close()
    
    if os.path.exists(test_path):
        os.remove(test_path)

def test_breach_radar_false_positive_probability():
    """Verify the Bloom Filter stays within its 1% mathematical error bound."""
    sensor = MockEnvironmentSensor(ram_mb=2048)
    # Force Efficiency Mode (RAM) for speed during testing
    radar = BreachRadarPlugin(sensor, is_enabled=True)
    
    # Fill with 1000 items
    for i in range(1000):
        radar.ingest_compromised_password(f"pwned_{i}")
        
    # Check 10,000 unique items to find false positives
    fp_count = 0
    for i in range(10000):
        if radar.is_compromised(f"safe_{i}"):
            fp_count += 1
            
    fp_rate = fp_count / 10000.0
    # Expected rate is 0.001 (0.1%) for RockYou mode. We allow up to 0.5% for variance.
    assert fp_rate < 0.005, f"FP Rate {fp_rate} exceeded mathematical bounds."