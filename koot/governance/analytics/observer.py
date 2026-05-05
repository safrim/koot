import time
import functools
from koot.governance.analytics.engine import telemetry

def observe_performance(operation_name: str):
    """Decorator to automatically log performance to the Analytics Engine."""
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

            telemetry.record(operation_name, duration_ms, bytes_count)
            return result
        return wrapper
    return decorator