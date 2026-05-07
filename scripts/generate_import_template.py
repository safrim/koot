import csv
import json
import os
import sys

MAPPING_DIR = "data/import_mappings"
KOOT_FIELDS = ["title", "username", "password", "uri", "notes", "tags"]

def generate_template_from_csv(csv_path: str, provider_name: str):
    """Intelligently generates a koot mapping template from a raw CSV file."""
    if not os.path.exists(csv_path):
        print(f"Error: Could not find CSV file at {csv_path}")
        sys.exit(1)

    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader) # Extract the first row (headers)

    print(f"\n--- Koot Intelligent Mapper: {provider_name.upper()} ---")
    print(f"Detected columns: {', '.join(headers)}\n")
    
    mapping = {}
    print("For each Koot internal field, type the matching column name from above.")
    print("Press Enter to skip if the column doesn't exist.\n")

    for field in KOOT_FIELDS:
        match = input(f"Match for Koot '{field}' -> ")
        if match.strip() in headers:
            mapping[field] = match.strip()
        elif match.strip():
            print(f"  [!] Warning: '{match}' is not in the detected columns, but adding anyway.")
            mapping[field] = match.strip()

    template = {
        "format": "csv",
        "map": mapping
    }

    os.makedirs(MAPPING_DIR, exist_ok=True)
    out_path = os.path.join(MAPPING_DIR, f"{provider_name}_csv.json")
    
    with open(out_path, 'w') as f:
        json.dump(template, f, indent=2)
        
    print(f"\n[+] Success! Template saved to {out_path}")
    print("[+] You can now use this template name in the Koot Import Engine.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generate_import_template.py <path_to_csv> <provider_name>")
        sys.exit(1)
    generate_template_from_csv(sys.argv[1], sys.argv[2])