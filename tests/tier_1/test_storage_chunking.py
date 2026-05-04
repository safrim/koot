import os
import tempfile
import unittest
from koot.storage.chunking.engine import AdaptiveChunker

class MockEnvironmentSensor:
    def __init__(self):
        self.low_memory = False
    def is_memory_low(self):
        return self.low_memory

class MockTelemetryEngine:
    def __init__(self, ratio=0.5):
        self.ratio = ratio
    def get_available_ram_ratio(self):
        return self.ratio

class MockOverrideMatrix:
    def __init__(self, active=False, val=None):
        self.active = active
        self.val = val
    def is_active(self, key):
        return self.active
    def get_value(self, key):
        return self.val

class TestAdaptiveChunkerExtended(unittest.TestCase):
    def setUp(self):
        self.sensor = MockEnvironmentSensor()
        self.chunker = AdaptiveChunker(self.sensor)

    def test_telemetry_scaling(self):
        self.chunker.telemetry = MockTelemetryEngine(ratio=0.9)
        self.chunker.stable_reads = 20
        self.chunker.current_chunk = 65536
        self.chunker._evaluate_hardware()
        self.assertEqual(self.chunker.current_chunk, 131072)

    def test_manual_override(self):
        self.chunker.override = MockOverrideMatrix(active=True, val=4096)
        self.chunker._evaluate_hardware()
        self.assertEqual(self.chunker.current_chunk, 4096)

if __name__ == '__main__':
    unittest.main()