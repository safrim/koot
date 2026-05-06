import json
import base64
import hmac
import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional
from koot.storage.chunking.buffered_adaptive import BufferedAdaptiveChunker
from koot.storage.integrity.merkle import MerkleTree


@dataclass
class EnvelopeHeader:
    """
    The standardized header for the Agnostic Envelope.
    Stores metadata required for decryption and integrity verification.
    """
    version: str
    content_type: str
    crypto_suite_id: str
    iv: str  # Base64 encoded Initialization Vector / Nonce
    merkle_root: str  # Base64 encoded Root Hash for integrity
    expires_at: Optional[float] = None  # Unix timestamp for TTL (Ghost Plugin)

class SecretEnvelope:
    """
    The universal container for all secrets in the koot ecosystem.
    Treats all data as a raw binary payload.
    """
    def __init__(self, header: EnvelopeHeader, payload: bytes):
        self.header = header
        self.payload = payload  # Raw encrypted bytes

    def serialize(self, vault_mac_key: bytes) -> bytes:
        """
        Packs the Envelope into a standardized JSON/Binary structure.
        Cryptographically signs the metadata (header) so background workers 
        can verify it without needing to decrypt the payload.
        """
        header_dict = asdict(self.header)
        # Sort keys to ensure deterministic byte output for the HMAC
        header_json_bytes = json.dumps(header_dict, sort_keys=True).encode('utf-8')
        
        # Generate an HMAC-SHA256 signature of the header using the Vault Key
        header_mac = hmac.new(vault_mac_key, header_json_bytes, hashlib.sha256).hexdigest()
        
        data = {
            "header": header_dict,
            "header_mac": header_mac,  # Cryptographic Proof of Integrity
            "payload": base64.b64encode(self.payload).decode('utf-8')
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def deserialize(cls, data: bytes) -> 'SecretEnvelope':
        """
        Unpacks a serialized Envelope byte string back into a SecretEnvelope object.
        Supports backwards compatibility for missing expires_at.
        """
        try:
            parsed = json.loads(data.decode('utf-8'))
            header_data = parsed.get("header", {})
            
            # Forward compatibility for older envelopes without TTL
            if "expires_at" not in header_data:
                header_data["expires_at"] = None
                
            header = EnvelopeHeader(**header_data)
            payload = base64.b64decode(parsed["payload"])
            return cls(header=header, payload=payload)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
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