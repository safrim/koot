import os

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

    def process_stream(self, file_path):
        with open(file_path, 'rb') as f:
            while True:
                self._evaluate_hardware()
                chunk = f.read(self.current_chunk)
                
                if not chunk:
                    break
                    
                self.stable_reads += 1
                yield chunk