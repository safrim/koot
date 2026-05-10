import os
import io

class AdaptiveChunker:
    def __init__(self, environment_sensor, telemetry_engine=None, override_matrix=None):
        self.env_sensor = environment_sensor
        self.telemetry = telemetry_engine
        self.override = override_matrix
        self.base_min = 16 * 1024  
        self.base_max = 64 * 1024  
        self.current_chunk = self.base_min
        self.stable_reads = 0
        self.ramp_up_threshold = 10 

    def _evaluate_hardware(self):
        if self.override and self.override.is_active('chunk_size'):
            self.current_chunk = self.override.get_value('chunk_size')
            return

        dynamic_max = self.base_max
        if self.telemetry:
            ram_available = self.telemetry.get_available_ram_ratio()
            if ram_available > 0.7:
                dynamic_max = 1024 * 1024  

        if self.env_sensor.is_memory_low():
            self.current_chunk = self.base_min
            self.stable_reads = 0
        elif self.stable_reads >= self.ramp_up_threshold and self.current_chunk < dynamic_max:
            self.current_chunk = min(self.current_chunk * 2, dynamic_max)
            self.stable_reads = 0

    def _stream_generator(self, stream):
        """Internal generator that dynamically chunks any open stream."""
        while True:
            self._evaluate_hardware()
            chunk = stream.read(self.current_chunk)
            
            if not chunk:
                break
                
            self.stable_reads += 1
            yield chunk

    def process_file(self, file_path):
        """For large physical media on disk."""
        with open(file_path, 'rb') as f:
            yield from self._stream_generator(f)

    def process_bytes(self, payload: bytes):
        """For in-memory secrets, without writing plaintext to disk."""
        stream = io.BytesIO(payload)
        yield from self._stream_generator(stream)