# koot/plugins/breach_radar.py
import hashlib
import math
import mmap
import os
import logging

class BreachRadarPlugin:
    """
    Offline Breach Radar (Opt-In).
    Countermeasure: Privacy-Preserving Breach Detection.
    
    Dynamically scales between:
    - Maximum Security: 1.3 Billion Items (HIBP) via Disk-Backing (mmap).
    - Efficiency: 15 Million Items (RockYou) via Disk-Backing (mmap).
    """
    
    def __init__(self, environment_sensor, is_enabled: bool = False, filepath="data/breach_radar.bin"):
        """
        :param environment_sensor: koot's core hardware sensor.
        :param is_enabled: User opt-in flag (defaults to False/Dormant).
        :param filepath: Path to the persistent Bloom Filter binary.
        """
        self.is_enabled = is_enabled
        self.sensor = environment_sensor
        self.filepath = os.path.abspath(filepath)
        
        # Internal state
        self.dataset_type = "dormant"
        self.m = 0 
        self.k = 0 
        self.bit_array = None
        self.file_obj = None
        
        if self.is_enabled:
            self._configure_based_on_hardware()

    def _configure_based_on_hardware(self):
        """Fulfills koot's 'Hardware-Driven Loading' principle."""
        available_disk = self.sensor.get_available_disk_mb()
        
        # MODE A: HIBP Full - 1.3 Billion Items
        # Requires ~1.56 GB Disk, ~0 MB RAM
        if available_disk > 10000: # 10GB safety buffer
            self.dataset_type = "hibp_full"
            expected_items = 1300000000 
            fp_rate = 0.01
        # MODE B: RockYou Lite - 15 Million Items (Full RockYou list coverage)
        # Requires ~26 MB Disk, ~0 MB RAM
        else:
            self.dataset_type = "rockyou_lite"
            expected_items = 15000000
            fp_rate = 0.001

        self.m = self._calculate_size(expected_items, fp_rate)
        self.k = self._calculate_hash_count(self.m, expected_items)
        
        self._mount_disk_filter()
        logging.info(f"Breach Radar: Initialized {self.dataset_type} at {self.filepath}")

    def _mount_disk_filter(self):
        """Creates the sparse file on disk and memory-maps it."""
        byte_size = (self.m + 7) // 8
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        
        if not os.path.exists(self.filepath):
            with open(self.filepath, "wb") as f:
                f.seek(byte_size - 1)
                f.write(b'\0')
                
        self.file_obj = open(self.filepath, "r+b")
        self.bit_array = mmap.mmap(self.file_obj.fileno(), 0)

    def ingest_compromised_password(self, password: str):
        if not self.is_enabled or self.bit_array is None: return
        for pos in self._get_positions(password):
            self.bit_array[pos // 8] |= (1 << (pos % 8))

    def is_compromised(self, password: str) -> bool:
        if not self.is_enabled or self.bit_array is None: return False
        for pos in self._get_positions(password):
            if (self.bit_array[pos // 8] & (1 << (pos % 8))) == 0:
                return False
        return True

    def _get_positions(self, password: str) -> list[int]:
        """Kirsch-Mitzenmacher optimization for efficient hashing."""
        base_hash = hashlib.sha1(password.encode('utf-8', errors='ignore')).digest()
        h1 = int.from_bytes(base_hash[:4], 'big')
        h2 = int.from_bytes(base_hash[4:8], 'big')
        return [(h1 + i * h2) % self.m for i in range(self.k)]

    def check_capabilities(self): return self.is_enabled

    def close(self):
        """Safely flushes and unmounts the filter."""
        if hasattr(self, 'bit_array') and self.bit_array:
            self.bit_array.flush()
            self.bit_array.close()
        if hasattr(self, 'file_obj') and self.file_obj:
            self.file_obj.close()

    def _calculate_size(self, n, p): return int(-(n * math.log(p)) / (math.log(2) ** 2))
    def _calculate_hash_count(self, m, n): return int((m / n) * math.log(2))