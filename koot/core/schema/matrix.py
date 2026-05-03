import logging
from enum import Enum
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class SchemaState(Enum):
    ACTIVE = "active"             # Can create and read
    TOMBSTONED = "tombstoned"     # Can read only (Legacy Read-Only)
    DEACTIVATED = "deactivated"   # Completely locked out (Attack surface minimization)

class SchemaMatrix:
    """
    The Dynamic Schema & Capability Matrix.
    Tracks, validates, and manages data types that koot is allowed to handle.
    """
    def __init__(self):
        # The queryable manifest of all loaded schemas
        self._schemas: Dict[str, Dict[str, Any]] = {}

    def plug_in(self, content_type: str, mapping_definition: dict) -> None:
        """
        Hot-Swapping Feature: Plugs in a new schema pack dynamically.
        By default, a plugged-in schema is ACTIVE (Opt-In logic).
        """
        self._schemas[content_type] = {
            "state": SchemaState.ACTIVE,
            "mapping": mapping_definition
        }
        logging.info(f"[SCHEMA] Plugged in and activated schema: {content_type}")

    def unplug_to_tombstone(self, content_type: str) -> None:
        """
        ENGINEERED COUNTERMEASURE: Schema Tombstoning
        Moves an active schema to a "Legacy Read-Only" state.
        """
        if content_type not in self._schemas:
            raise ValueError(f"Cannot tombstone unknown schema: {content_type}")
        
        self._schemas[content_type]["state"] = SchemaState.TOMBSTONED
        logging.warning(f"[SCHEMA] Tombstoned schema: {content_type}. Creation blocked, Read permitted.")

    def deactivate_schema(self, content_type: str) -> None:
        """
        Opt-In Logic: Actively rejects data types to minimize attack surface.
        """
        if content_type not in self._schemas:
            raise ValueError(f"Cannot deactivate unknown schema: {content_type}")
        
        self._schemas[content_type]["state"] = SchemaState.DEACTIVATED
        logging.warning(f"[SCHEMA] Deactivated schema: {content_type}. All access blocked.")

    def get_queryable_manifest(self) -> List[str]:
        """Outputs a comprehensive list of every ACTIVE data type it can handle."""
        return [
            ctype for ctype, data in self._schemas.items() 
            if data["state"] == SchemaState.ACTIVE
        ]

    def validate_for_creation(self, content_type: str) -> bool:
        """
        Checks if the system is allowed to CREATE new data of this type.
        """
        if content_type not in self._schemas:
            logging.error(f"[SCHEMA REJECTED] Unknown data type: {content_type}")
            raise PermissionError(f"Schema '{content_type}' is unknown and not opted-in.")
            
        state = self._schemas[content_type]["state"]
        
        if state == SchemaState.TOMBSTONED:
            logging.error(f"[SCHEMA REJECTED] Schema '{content_type}' is Tombstoned (Legacy Read-Only).")
            raise PermissionError(f"Cannot create new data for tombstoned schema: {content_type}")
            
        if state == SchemaState.DEACTIVATED:
            logging.error(f"[SCHEMA REJECTED] Schema '{content_type}' is completely deactivated.")
            raise PermissionError(f"Access denied for deactivated schema: {content_type}")
            
        return True

    def validate_for_reading(self, content_type: str) -> bool:
        """
        Checks if the system is allowed to READ/DECRYPT data of this type.
        Allows ACTIVE and TOMBSTONED, but blocks DEACTIVATED or UNKNOWN.
        """
        if content_type not in self._schemas:
            raise PermissionError(f"Schema '{content_type}' is unknown.")
            
        state = self._schemas[content_type]["state"]
        
        if state == SchemaState.DEACTIVATED:
            raise PermissionError(f"Cannot read deactivated schema: {content_type}")
            
        # Permits both ACTIVE and TOMBSTONED
        return True
        
    def get_mapping(self, content_type: str) -> dict:
        """Retrieves the decryption mapping if reading is validated."""
        self.validate_for_reading(content_type)
        return self._schemas[content_type]["mapping"]