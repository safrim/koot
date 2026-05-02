import json
import base64
from dataclasses import dataclass, asdict
from typing import Dict, Any

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

class SecretEnvelope:
    """
    The universal container for all secrets in the koot ecosystem.
    Treats all data as a raw binary payload.
    """
    def __init__(self, header: EnvelopeHeader, payload: bytes):
        self.header = header
        self.payload = payload  # Raw encrypted bytes

    def serialize(self) -> bytes:
        """
        Packs the Envelope into a standardized JSON/Binary structure.
        The payload is Base64 encoded to safely reside within JSON.
        """
        data = {
            "header": asdict(self.header),
            "payload": base64.b64encode(self.payload).decode('utf-8')
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def deserialize(cls, data: bytes) -> 'SecretEnvelope':
        """
        Unpacks a serialized Envelope byte string back into a SecretEnvelope object.
        """
        try:
            parsed = json.loads(data.decode('utf-8'))
            header = EnvelopeHeader(**parsed["header"])
            payload = base64.b64decode(parsed["payload"])
            return cls(header=header, payload=payload)
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            raise ValueError(f"Failed to deserialize Secret Envelope: {e}")

    def __repr__(self):
        return f"<SecretEnvelope Type:{self.header.content_type} Version:{self.header.version}>"