import time
import psutil
import threading
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class MetricEntry:
    timestamp: float
    operation: str
    duration_ms: float
    bytes_processed: int = 0
    memory_usage_kb: float = 0.0
    tenant_id: str = "SYSTEM_CORE"  # ADDED: Tenant context

class AnalyticsEngine:
    def __init__(self):
        self._metrics: List[MetricEntry] = []
        self._lock = threading.Lock()
        self._process = psutil.Process()

    def record(self, operation: str, duration_ms: float, bytes_processed: int = 0, tenant_id: str = "SYSTEM_CORE"):
        """Records a single performance event, now tagged with a tenant ID."""
        mem_info = self._process.memory_info().rss / 1024  # KB
        
        entry = MetricEntry(
            timestamp=time.time(),
            operation=operation,
            duration_ms=duration_ms,
            bytes_processed=bytes_processed,
            memory_usage_kb=mem_info,
            tenant_id=tenant_id
        )
        
        with self._lock:
            self._metrics.append(entry)

    def get_report(self) -> Dict[str, Any]:
        """Generates a real-time JSON-ready state report with tenant categorization."""
        with self._lock:
            if not self._metrics:
                return {"status": "no_data"}

            total_ops = len(self._metrics)
            avg_duration = sum(m.duration_ms for m in self._metrics) / total_ops
            total_bytes = sum(m.bytes_processed for m in self._metrics)
            
            # Group metrics by tenant to fully categorize the logs
            tenant_breakdown = {}
            for m in self._metrics:
                if m.tenant_id not in tenant_breakdown:
                    tenant_breakdown[m.tenant_id] = {"operations": 0, "throughput_bytes": 0}
                tenant_breakdown[m.tenant_id]["operations"] += 1
                tenant_breakdown[m.tenant_id]["throughput_bytes"] += m.bytes_processed
            
            return {
                "summary": {
                    "total_operations": total_ops,
                    "avg_latency_ms": round(avg_duration, 4),
                    "total_throughput_bytes": total_bytes,
                    "current_memory_kb": round(self._process.memory_info().rss / 1024, 2),
                    "tenant_breakdown": tenant_breakdown  # ADDED: Per-tenant summary
                },
                "raw_log": [asdict(m) for m in self._metrics[-10:]]  # Last 10 entries (includes tenant_id)
            }

    def flush(self):
        """Clears the metrics buffer."""
        with self._lock:
            self._metrics = []

# Global instance for the bus to mount
telemetry = AnalyticsEngine()