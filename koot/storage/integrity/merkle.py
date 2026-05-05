import hashlib
import base64
from typing import List, Tuple

class MerkleTree:
    """
    Phase 3: Session 9 - Merkle Tree Integrity
    Generates a hash tree to cryptographically link all chunks.
    """
    def __init__(self):
        self.leaves = []
        self.tree = []

    @staticmethod
    def hash_chunk(chunk: bytes) -> bytes:
        """Hashes a single 64KB chunk using SHA-256."""
        return hashlib.sha256(chunk).digest()

    @staticmethod
    def hash_pair(left: bytes, right: bytes) -> bytes:
        """Hashes two child nodes to form a parent node."""
        return hashlib.sha256(left + right).digest()

    def add_chunk(self, chunk: bytes):
        """Adds a chunk's hash to the leaves of the tree."""
        self.leaves.append(self.hash_chunk(chunk))

    def build(self):
        """Builds the Merkle Tree from the leaves up to the root."""
        if not self.leaves:
            self.tree = []
            return
        
        level = self.leaves
        self.tree = [level]
        
        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                # If there's an odd number of nodes, duplicate the last one
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(self.hash_pair(left, right))
            level = next_level
            self.tree.append(level)

    def get_root_hash(self) -> str:
        """Returns the Base64-encoded Root Hash for the Envelope Header."""
        if not self.tree:
            return ""
        return base64.b64encode(self.tree[-1][0]).decode('utf-8')

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """
        Generates the cryptographic path needed to verify a specific chunk.
        Returns a list of tuples: (sibling_hash, is_sibling_on_left)
        """
        proof = []
        if not self.tree:
            return proof
            
        curr_index = index
        for i in range(len(self.tree) - 1):
            level = self.tree[i]
            is_left_node = (curr_index % 2 == 0)
            
            if is_left_node:
                sibling_index = curr_index + 1 if curr_index + 1 < len(level) else curr_index
            else:
                sibling_index = curr_index - 1
                
            proof.append((level[sibling_index], not is_left_node))
            curr_index //= 2
            
        return proof


class StreamingVerifier:
    """
    [Engineered Countermeasure: Lazy Verification & Caching]
    Verifies a single chunk actively being accessed without calculating the entire tree.
    """
    @staticmethod
    def verify_chunk(chunk: bytes, proof: List[Tuple[bytes, bool]], expected_root: str) -> bool:
        """
        Validates the chunk's integrity by climbing the tree using the proof path.
        """
        current_hash = MerkleTree.hash_chunk(chunk)
        
        # Traverse up the tree using the proof
        for sibling_hash, is_sibling_left in proof:
            if is_sibling_left:
                current_hash = MerkleTree.hash_pair(sibling_hash, current_hash)
            else:
                current_hash = MerkleTree.hash_pair(current_hash, sibling_hash)
                
        calculated_root = base64.b64encode(current_hash).decode('utf-8')
        return calculated_root == expected_root