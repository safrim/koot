import hashlib
import base64
import sqlite3
import tempfile
import os
from typing import List, Tuple

class MerkleTree:
    """
    Phase 3: Session 3.1 - Out-of-Core Merkle Tree Construction
    Generates a hash tree to cryptographically link all chunks using a disk-backed store
    to prevent OOM crashes on multi-gigabyte files.
    """
    def __init__(self):
        # Create a temporary disk-backed SQLite database to store tree nodes
        self.db_fd, self.db_path = tempfile.mkstemp(suffix='.db', prefix='koot_merkle_')
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        
        # Schema: stores the tree level, node index on that level, and the hash
        self.cursor.execute('''
            CREATE TABLE nodes (
                level INTEGER,
                idx INTEGER,
                hash BLOB,
                PRIMARY KEY (level, idx)
            )
        ''')
        self.conn.commit()
        
        self.leaf_count = 0
        self.max_level = 0

    def __del__(self):
        # Secure cleanup: destroy the temporary database when the tree is deallocated
        try:
            self.conn.close()
            os.close(self.db_fd)
            os.remove(self.db_path)
        except Exception:
            pass

    @staticmethod
    def hash_chunk(chunk: bytes) -> bytes:
        """Hashes a single 64KB chunk using SHA-256."""
        return hashlib.sha256(chunk).digest()

    @staticmethod
    def hash_pair(left: bytes, right: bytes) -> bytes:
        """Hashes two child nodes to form a parent node."""
        return hashlib.sha256(left + right).digest()

    def add_chunk(self, chunk: bytes):
        """Adds a chunk's hash to the leaves (level 0) of the tree in the disk-backed store."""
        chunk_hash = self.hash_chunk(chunk)
        self.cursor.execute('INSERT INTO nodes (level, idx, hash) VALUES (?, ?, ?)',
                            (0, self.leaf_count, chunk_hash))
        self.leaf_count += 1
        
    def build(self):
        """Builds the Merkle Tree from the leaves up to the root, level by level, out-of-core."""
        self.conn.commit()
        if self.leaf_count == 0:
            return

        current_level = 0
        current_level_count = self.leaf_count

        # BUGFIX: Use separate cursors for reading and writing so the INSERT 
        # statement doesn't overwrite the SELECT statement's iteration state.
        read_cursor = self.conn.cursor()
        write_cursor = self.conn.cursor()

        while current_level_count > 1:
            next_level_count = 0
            
            # Fetch nodes from the current level iteratively
            read_cursor.execute('SELECT hash FROM nodes WHERE level = ? ORDER BY idx ASC', (current_level,))
            
            while True:
                left_row = read_cursor.fetchone()
                if not left_row:
                    break  # Finished processing this level
                
                left_hash = left_row[0]
                right_row = read_cursor.fetchone()
                
                # If odd number of nodes, duplicate the last one
                right_hash = right_row[0] if right_row else left_hash 
                    
                parent_hash = self.hash_pair(left_hash, right_hash)
                
                write_cursor.execute('INSERT INTO nodes (level, idx, hash) VALUES (?, ?, ?)',
                                    (current_level + 1, next_level_count, parent_hash))
                next_level_count += 1

            self.conn.commit()
            current_level += 1
            current_level_count = next_level_count
            
        self.max_level = current_level

    def get_root_hash(self) -> str:
        """Returns the Base64-encoded Root Hash for the Envelope Header."""
        if self.leaf_count == 0:
            return ""
        
        self.cursor.execute('SELECT hash FROM nodes WHERE level = ? AND idx = 0', (self.max_level,))
        row = self.cursor.fetchone()
        if row:
            return base64.b64encode(row[0]).decode('utf-8')
        return ""

    def get_proof(self, index: int) -> List[Tuple[bytes, bool]]:
        """
        Generates the cryptographic path needed to verify a specific chunk.
        Returns a list of tuples: (sibling_hash, is_sibling_on_left)
        """
        proof = []
        if self.leaf_count == 0:
            return proof
            
        curr_index = index
        for level in range(self.max_level):
            is_left_node = (curr_index % 2 == 0)
            
            if is_left_node:
                sibling_index = curr_index + 1
                # Check if sibling exists, otherwise node was duplicated
                self.cursor.execute('SELECT 1 FROM nodes WHERE level = ? AND idx = ?', (level, sibling_index))
                if not self.cursor.fetchone():
                    sibling_index = curr_index
            else:
                sibling_index = curr_index - 1
                
            self.cursor.execute('SELECT hash FROM nodes WHERE level = ? AND idx = ?', (level, sibling_index))
            sibling_row = self.cursor.fetchone()
            sibling_hash = sibling_row[0] if sibling_row else b'' 
            
            proof.append((sibling_hash, not is_left_node))
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
        
        for sibling_hash, is_sibling_left in proof:
            if is_sibling_left:
                current_hash = MerkleTree.hash_pair(sibling_hash, current_hash)
            else:
                current_hash = MerkleTree.hash_pair(current_hash, sibling_hash)
                
        calculated_root = base64.b64encode(current_hash).decode('utf-8')
        return calculated_root == expected_root