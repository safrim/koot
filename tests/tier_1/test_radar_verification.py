# tests/tier_1/test_breach_radar.py
import pytest
import os
from koot.plugins.breach_radar import BreachRadarPlugin
from koot.core.bus.contracts import ContractEnforcer

class MockSensor:
    def get_available_disk_mb(self): return 500

def test_breach_radar_contract():
    radar = BreachRadarPlugin(MockSensor())
    assert ContractEnforcer.verify_tier_1(radar, ['is_compromised', 'ingest_compromised_password']) is True

def test_breach_radar_persistence():
    test_path = "data/test_radar.bin"
    sensor = MockSensor()
    
    # Session 1: Ingest
    radar = BreachRadarPlugin(sensor, is_enabled=True, filepath=test_path)
    radar.ingest_compromised_password("koot_secret_2026")
    radar.close()
    
    # Session 2: Reload and Check
    radar_reload = BreachRadarPlugin(sensor, is_enabled=True, filepath=test_path)
    assert radar_reload.is_compromised("koot_secret_2026") is True
    radar_reload.close()
    
    if os.path.exists(test_path): os.remove(test_path)