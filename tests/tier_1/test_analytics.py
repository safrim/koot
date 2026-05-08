import pytest
import time
import json
from koot.governance.analytics.engine import telemetry
from koot.governance.analytics.observer import observe_performance

# Updated dummy work to accept tenant_id simulating the Gateway context
@observe_performance("test_op")
def dummy_work(data: bytes, tenant_id: str = "SYSTEM_CORE"):
    time.sleep(0.01)  # Simulate 10ms work
    return True

def test_telemetry_collection_tenant_aware():
    telemetry.flush()
    
    # Trigger observed function with a specific sub-user
    dummy_work(b"0" * 1024, tenant_id="Operative_Alpha")
    
    report = telemetry.get_report()
    
    assert report["summary"]["total_operations"] >= 1
    assert report["summary"]["total_throughput_bytes"] >= 1024
    assert report["summary"]["avg_latency_ms"] >= 10
    assert "current_memory_kb" in report["summary"]

def test_telemetry_json_serialization():
    telemetry.flush()
    dummy_work(b"test", tenant_id="Operative_Beta")
    
    report = telemetry.get_report()
    
    # Ensure the report remains JSON serializable after adding tenant contexts
    json_string = json.dumps(report)
    assert isinstance(json_string, str)
    
    # Verify we can load it back seamlessly
    parsed = json.loads(json_string)
    assert parsed["summary"]["total_operations"] >= 1