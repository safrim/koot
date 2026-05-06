# tests/tier_1/test_breach_radar.py
import pytest
from koot.plugins.breach_radar import BreachRadarPlugin
from koot.core.bus.contracts import ContractEnforcer

def test_breach_radar_contract_compliance():
    """Ensure the plugin complies with the Tier 1 Contract Enforcer."""
    radar = BreachRadarPlugin()
    # Verifying it has the required interface for the Registry Bus
    required_methods = ['is_compromised', 'ingest_compromised_password']
    assert ContractEnforcer.verify_tier_1(radar, required_methods) is True

def test_breach_radar_offline_detection():
    """Test deterministic true positives and true negatives."""
    radar = BreachRadarPlugin(expected_items=1000, fp_rate=0.01)
    
    known_compromised = ["password123", "admin", "qwerty", "iloveyou"]
    safe_passwords = ["My$uperS3cretV@ult!", "Koot#Resilient2026", "CorrectHorseBatteryStaple"]
    
    # 1. Ingest the breached dataset
    for p in known_compromised:
        radar.ingest_compromised_password(p)
        
    # 2. Verify deterministic detection (True Positives)
    for p in known_compromised:
        assert radar.is_compromised(p) is True, f"Failed to detect compromised password: {p}"
        
    # 3. Verify True Negatives (No false positives in this controlled small sample)
    for p in safe_passwords:
        assert radar.is_compromised(p) is False, f"Flagged a safe password as compromised: {p}"
        
def test_breach_radar_false_positive_bounds():
    """Verify the mathematical bounds of the Bloom filter hold up at scale."""
    target_fp_rate = 0.05  # 5% acceptable false positive rate for the test
    radar = BreachRadarPlugin(expected_items=1000, fp_rate=target_fp_rate)
    
    # Fill the filter with 1000 items
    for i in range(1000):
        radar.ingest_compromised_password(f"pwned_pass_{i}")
        
    # Test 10,000 unknown items
    false_positives = 0
    for i in range(10000):
        if radar.is_compromised(f"safe_pass_{i}"):
            false_positives += 1
            
    fp_ratio = false_positives / 10000.0
    
    # The actual false positive rate should remain close to the 5% target.
    # We assert it remains below 7% to account for minor probabilistic variance.
    assert fp_ratio < 0.07, f"False positive rate ({fp_ratio}) exceeded mathematical bounds!"