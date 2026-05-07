import csv
import json
import io
from typing import List, Dict, Any

class DataReader:
    """Handles raw data ingestion and parsing based on format."""
    
    @staticmethod
    def parse(raw_data: str, format_type: str, root_key: str = None) -> List[Dict[str, Any]]:
        if format_type == "csv":
            return DataReader._parse_csv(raw_data)
        elif format_type == "json":
            return DataReader._parse_json(raw_data, root_key)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    @staticmethod
    def _parse_csv(raw_data: str) -> List[Dict[str, Any]]:
        f = io.StringIO(raw_data.strip())
        return list(csv.DictReader(f))

    @staticmethod
    def _parse_json(raw_data: str, root_key: str = None) -> List[Dict[str, Any]]:
        parsed = json.loads(raw_data)
        return parsed.get(root_key, []) if root_key else parsed