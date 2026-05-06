import os
import psutil
import logging

logger = logging.getLogger(__name__)

class BufferedAdaptiveChunker:
    """
    Implements Logical vs. Physical Chunking.
    Protects memory via dynamic I/O reads, while protecting Merkle integrity 
    via fixed-size cryptographic yields.
    """
    def __init__(self, logical_chunk_size: int = 65536):
        # The strict boundary required by the Merkle Tree (64KB)
        self.logical_chunk_size = logical_chunk_size 
        
        # The dynamic boundary used for safe disk reads (Starts at 16KB)
        self.current_physical_size = 16384           
        self.buffer = bytearray()

    def _evaluate_hardware(self):
        """
        Evaluates real-time system memory to dynamically throttle physical read sizes.
        Countermeasure against OOM crashes on memory-constrained devices while maintaining
        strict logical boundaries for cryptographic operations.
        """
        try:
            # Probe real-time virtual memory statistics
            mem = psutil.virtual_memory()
            available_mb = mem.available / (1024 * 1024)

            if available_mb < 512:
                # Critical RAM: Extremely aggressive throttling
                # Limit physical reads to 16KB
                if self.current_physical_size != 16384:
                    logger.warning("CRITICAL: Low memory detected. Throttling disk I/O to 16KB reads.")
                    self.current_physical_size = 16384
                
            elif available_mb < 2048:
                # Constrained RAM
                # Limit physical reads to 64KB
                if self.current_physical_size != 65536:
                    logger.info("Constrained memory detected. Scaling disk I/O to 64KB reads.")
                    self.current_physical_size = 65536
                
            else:
                # Abundant RAM: Optimize for speed and lower I/O overhead
                # Read 1MB physical chunks at a time
                if self.current_physical_size != 1048576:
                    self.current_physical_size = 1048576
                
        except Exception as e:
            # Failsafe: If telemetry fails, default to a highly defensive posture (16KB reads)
            if self.current_physical_size != 16384:
                logger.error(f"Hardware sensor evaluation failed: {e}. Defaulting to safe 16KB reads.")
                self.current_physical_size = 16384

    def process_stream(self, file_path: str):
        """
        Reads files dynamically but strictly yields 64KB logical blocks.
        """
        with open(file_path, 'rb') as f:
            while True:
                # 1. Evaluate hardware BEFORE the read (Protects RAM)
                self._evaluate_hardware()
                
                # 2. Read a physical block based on current hardware state
                physical_chunk = f.read(self.current_physical_size)
                
                if not physical_chunk:
                    # EOF reached. Yield any remaining trailing bytes in buffer.
                    if self.buffer:
                        yield bytes(self.buffer)
                        self.buffer.clear()
                    break
                    
                # 3. Accumulate physical reads into the buffer
                self.buffer.extend(physical_chunk)
                
                # 4. Yield ONLY when the strict cryptographic boundary is met
                while len(self.buffer) >= self.logical_chunk_size:
                    # Extract exactly 64KB
                    logical_chunk = self.buffer[:self.logical_chunk_size]
                    
                    # Truncate the buffer
                    del self.buffer[:self.logical_chunk_size]
                    
                    # Send to the Merkle Tree / Crypto Engine
                    yield bytes(logical_chunk)