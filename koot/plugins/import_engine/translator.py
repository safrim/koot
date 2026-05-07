from typing import Dict, Any

class SchemaTranslator:
    """Normalizes external dictionaries into koot Envelopes."""
    
    @staticmethod
    def translate(source_item: Dict[str, Any], mapping: Dict[str, str]) -> Dict[str, Any]:
        return {
            "schema_version": "2026.1",
            "type": "credential",
            "content": {
                "title": SchemaTranslator._get_nested(source_item, mapping.get("title", "")),
                "username": SchemaTranslator._get_nested(source_item, mapping.get("username", "")),
                "password": SchemaTranslator._get_nested(source_item, mapping.get("password", "")),
                "uri": SchemaTranslator._get_nested(source_item, mapping.get("uri", "")),
                "notes": SchemaTranslator._get_nested(source_item, mapping.get("notes", ""))
            },
            "tags": [SchemaTranslator._get_nested(source_item, mapping.get("tags", "Imported"))]
        }

    @staticmethod
    def _get_nested(d: Dict[str, Any], key_path: str) -> Any:
        if not key_path: return ""
        keys = key_path.split('.')
        val = d
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k, "")
            elif isinstance(val, list) and k.isdigit():
                val = val[int(k)] if int(k) < len(val) else ""
            else:
                return ""
        return val