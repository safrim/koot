import pytest
import time
import json  # Added missing import
from koot.governance.analytics.engine import telemetry
from koot.governance.analytics.observer import observe_performance

@observe_performance("test_op")
def dummy_work(data: bytes):
    time.sleep(0.01)  # Simulate 10ms work
    return True

def test_telemetry_collection():
    telemetry.flush()
    
    # Trigger observed function
    dummy_work(b"0" * 1024)  # 1KB
    
    report = telemetry.get_report()
    
    assert report["summary"]["total_operations"] == 1
    assert report["summary"]["total_throughput_bytes"] == 1024
    assert report["summary"]["avg_latency_ms"] >= 10
    assert "current_memory_kb" in report["summary"]

def test_telemetry_json_serialization():
    telemetry.flush()
    dummy_work(b"test")
    
    report = telemetry.get_report()
    # Ensure it's JSON serializable
    json_string = json.dumps(report)
    assert isinstance(json_string, str)
    
    # Verify we can load it back
    parsed = json.loads(json_string)
    assert parsed["summary"]["total_operations"] == 1