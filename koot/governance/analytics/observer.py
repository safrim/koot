import time
import functools
import logging
from koot.governance.analytics.engine import telemetry

def observe_performance(operation_name: str):
    """
    Decorator to automatically log performance to the Analytics Engine.
    Now intercepts the tenant_id to provide Tenant-Aware Analytics.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            # Execute the actual function
            result = func(*args, **kwargs)
            
            end_time = time.perf_counter()
            duration_ms = (end_time - start_time) * 1000
            
            # Estimate bytes processed if the first arg is bytes
            bytes_count = 0
            if args and isinstance(args[0], (bytes, bytearray)):
                bytes_count = len(args[0])
            elif "data" in kwargs and isinstance(kwargs["data"], (bytes, bytearray)):
                bytes_count = len(kwargs["data"])

            # Intercept tenant_id from kwargs. 
            # If the operation is internal/system-level, it defaults to SYSTEM_CORE.
            tenant_id = kwargs.get("tenant_id", "SYSTEM_CORE")

            try:
                # Pass tenant_id to the telemetry engine
                telemetry.record(
                    operation_name, 
                    duration_ms, 
                    bytes_count, 
                    tenant_id=tenant_id
                )
            except TypeError:
                # Fallback: If engine.py hasn't been updated to accept tenant_id yet,
                # we temporarily append the tenant_id to the operation name.
                telemetry.record(f"{operation_name}::{tenant_id}", duration_ms, bytes_count)
                
            return result
        return wrapper
    return decorator