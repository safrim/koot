# koot/plugins/breach_radar.py
import hashlib
import math

class BreachRadarPlugin:
    """
    Offline Breach Radar (Local Bloom Filters).
    Countermeasure: Privacy-Preserving Breach Detection.
    Allows koot to query if a password has been compromised using a 
    highly compressed local probabilistic data structure.
    """
    
    def __init__(self, expected_items: int = 1000000, fp_rate: float = 0.001):
        """
        Initializes the Bloom Filter.
        :param expected_items: The estimated number of breached passwords to ingest.
        :param fp_rate: The acceptable false-positive probability (e.g., 0.1%).
        """
        self.expected_items = expected_items
        self.fp_rate = fp_rate
        
        # Calculate optimal bit array size (m) and hash function count (k)
        self.m = self._calculate_size(expected_items, fp_rate)
        self.k = self._calculate_hash_count(self.m, expected_items)
        
        # Using bytearray for memory-efficient bit manipulation
        self.bit_array = bytearray((self.m + 7) // 8)

    def _calculate_size(self, n: int, p: float) -> int:
        """Returns optimal size of bit array (m)."""
        return int(-(n * math.log(p)) / (math.log(2) ** 2))

    def _calculate_hash_count(self, m: int, n: int) -> int:
        """Returns optimal number of hash functions (k)."""
        return int((m / n) * math.log(2))

    def _get_positions(self, password: str) -> list[int]:
        """
        Uses the Kirsch-Mitzenmacher optimization to derive k hash functions 
        from a single SHA-1 base hash.
        """
        base_hash = hashlib.sha1(password.encode('utf-8')).digest()
        
        # Split the 160-bit SHA-1 hash into two 32-bit integers
        hash1 = int.from_bytes(base_hash[:4], 'big')
        hash2 = int.from_bytes(base_hash[4:8], 'big')
        
        positions = []
        for i in range(self.k):
            # h_i(x) = (h1(x) + i * h2(x)) % m
            pos = (hash1 + i * hash2) % self.m
            positions.append(pos)
            
        return positions

    def _set_bit(self, pos: int):
        byte_index = pos // 8
        bit_index = pos % 8
        self.bit_array[byte_index] |= (1 << bit_index)

    def _get_bit(self, pos: int) -> bool:
        byte_index = pos // 8
        bit_index = pos % 8
        return (self.bit_array[byte_index] & (1 << bit_index)) != 0

    def ingest_compromised_password(self, password: str):
        """Adds a compromised password to the local Bloom Filter."""
        for pos in self._get_positions(password):
            self._set_bit(pos)

    def is_compromised(self, password: str) -> bool:
        """
        Checks if a password is in the Bloom Filter.
        Returns True if PROBABLY compromised.
        Returns False if DEFINITELY NOT compromised.
        """
        for pos in self._get_positions(password):
            if not self._get_bit(pos):
                return False
        return True
        
    def check_capabilities(self) -> bool:
        """Fulfills a basic signature check for ContractEnforcer."""
        return True