import os
import json
import logging
from typing import Dict
from .reader import DataReader
from .translator import SchemaTranslator

class ImportEnginePlugin:
    def __init__(self, registry_bus, mapping_dir: str = "data/import_mappings"):
        self.bus = registry_bus
        self.mapping_dir = os.path.abspath(mapping_dir)

    def process_import(self, provider_template: str, raw_data: str) -> Dict[str, int]:
        template_path = os.path.join(self.mapping_dir, f"{provider_template}.json")
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template missing: {template_path}")

        with open(template_path, 'r') as f:
            template = json.load(f)

        # Stage 1 & 2: Parse
        raw_items = DataReader.parse(raw_data, template.get("format", "csv"), template.get("root_key"))
        
        vaulted_count = 0
        for item in raw_items:
            # Stage 3: Translate
            normalized_item = SchemaTranslator.translate(item, template.get("map", {}))
            # Stage 4: Dispatch
            self.bus.dispatch("storage", "vault_secret", payload=normalized_item)
            vaulted_count += 1

        logging.info(f"Vaulted {vaulted_count} items via {provider_template}.")
        return {"vaulted": vaulted_count}

    def check_capabilities(self):
        return True