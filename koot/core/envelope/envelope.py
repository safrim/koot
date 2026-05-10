import json
import base64
import hmac
import hashlib
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional, List
from koot.storage.chunking.buffered_adaptive import BufferedAdaptiveChunker
from koot.storage.integrity.merkle import MerkleTree

@dataclass
class EnvelopeHeader:
    """
    The standardized header for the Agnostic Envelope.
    Stores metadata required for decryption, integrity, and routing.
    """
    version: str
    content_type: str
    crypto_suite_id: str
    iv: str  
    merkle_root: str  
    expires_at: Optional[float] = None  # Opt-in Time-To-Live (TTL)
    
    # Plaintext tags exist ONLY in active memory (RAM). 
    # They are never written to the hard drive in plaintext.
    tags: List[str] = field(default_factory=list) 

class SecretEnvelope:
    """
    The universal container for all secrets in the koot ecosystem.
    Treats all data as a raw binary payload.
    """
    def __init__(self, header: EnvelopeHeader, payload: bytes):
        self.header = header
        self.payload = payload  

    def serialize(self, vault_mac_key: bytes) -> bytes:
        """
        Packs the Envelope into a standardized JSON/Binary structure.
        Cryptographically blinds metadata to prevent leakage and signs 
        the header to prevent Confused Deputy tampering attacks.
        """
        header_dict = asdict(self.header)
        
        # =================================================================
        # BLIND INDEXING: Cryptographically mask the categories/tags
        # =================================================================
        # 1. Remove plaintext tags from the dictionary being saved to disk
        plaintext_tags = header_dict.pop("tags", [])
        blind_tags = []
        
        for tag in plaintext_tags:
            # Normalize the path so "Finance" and "finance" hash identically
            normalized_tag = tag.strip().lower()
            tag_hash = hmac.new(vault_mac_key, normalized_tag.encode('utf-8'), hashlib.sha256).hexdigest()
            blind_tags.append(tag_hash)
            
        # 2. Inject the blinded hashes into the dictionary
        header_dict["blind_tags"] = blind_tags
        
        # =================================================================
        # AUTHENTICATED METADATA: Seal the JSON to prevent tampering
        # =================================================================
        # Sort keys to ensure deterministic byte output for the HMAC signature
        header_json_bytes = json.dumps(header_dict, sort_keys=True).encode('utf-8')
        
        # Generate an HMAC-SHA256 signature of the blinded header
        header_mac = hmac.new(vault_mac_key, header_json_bytes, hashlib.sha256).hexdigest()
        
        # 3. Assemble the final package
        data = {
            "header": header_dict,
            "header_mac": header_mac,  # Cryptographic Proof of Integrity
            "payload": base64.b64encode(self.payload).decode('utf-8')
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def deserialize(cls, data: bytes) -> 'SecretEnvelope':
        """
        Unpacks a serialized Envelope. Notice that this only loads the 
        BLIND hashes into the `tags` property. The upper-level core will 
        overwrite them with plaintext tags once the AES payload is decrypted.
        """
        try:
            parsed = json.loads(data.decode('utf-8'))
            header_data = parsed.get("header", {})
            
            # Forward compatibility for older envelopes
            if "expires_at" not in header_data:
                header_data["expires_at"] = None
            if "blind_tags" not in header_data:
                header_data["blind_tags"] = [] 
                
            header = EnvelopeHeader(
                version=header_data.get("version"),
                content_type=header_data.get("content_type"),
                crypto_suite_id=header_data.get("crypto_suite_id"),
                iv=header_data.get("iv"),
                merkle_root=header_data.get("merkle_root"),
                expires_at=header_data.get("expires_at"),
                tags=header_data.get("blind_tags") # temporarily load hashes into RAM
            )
            
            # validate=True ensures it strictly fails on invalid base64 strings
            payload = base64.b64decode(parsed["payload"], validate=True)
            return cls(header=header, payload=payload)
            
        # ADDED ValueError HERE to catch base64/binascii decoding errors
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
            raise ValueError(f"Failed to deserialize Secret Envelope: {e}")

    def __repr__(self):
        return f"<SecretEnvelope Type:{self.header.content_type} Version:{self.header.version}>"


def process_file_for_storage(file_path: str):
    """
    Phase 3 Media Handling Helper
    """
    chunker = BufferedAdaptiveChunker()
    tree = MerkleTree()

    for chunk in chunker.process_stream(file_path):
        tree.add_chunk(chunk)

    tree.build()
    header_root_hash = tree.get_root_hash()
    
    return header_root_hash