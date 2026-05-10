#!/usr/bin/env python3

import os
import logging
from pathlib import Path

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def create_koot_structure(base_path: str = "."):
    """
    Automates the creation of the koot Domain-Driven file structure.
    """
    root_dir = Path(base_path)
    
    # Define the directory tree
    directories = [
        "koot/core/bus",
        "koot/core/envelope",
        "koot/core/schema",
        "koot/crypto/classical",
        "koot/crypto/post_quantum",
        "koot/crypto/combiner",
        "koot/identity/derivation",
        "koot/identity/machine",
        "koot/storage/chunking",
        "koot/storage/integrity",
        "koot/storage/adapters",
        "koot/storage/migration",
        "koot/network/ipc",
        "koot/network/gateway",
        "koot/governance/analytics",
        "koot/governance/audit",
        "koot/governance/override",
        "tests/tier_1",
        "tests/integration",
        "scripts",
        "docs"
    ]

    logging.info(f"Initializing koot architecture at: {root_dir.absolute()}")

    # Create directories and __init__.py files
    for dir_path in directories:
        full_path = root_dir / dir_path
        
        # Create the directory, including parents
        full_path.mkdir(parents=True, exist_ok=True)
        logging.info(f"Created directory: {dir_path}")
        
        # If it's part of the python source code (koot or tests), make it a package
        if dir_path.startswith("koot") or dir_path.startswith("tests"):
            init_file = full_path / "__init__.py"
            if not init_file.exists():
                init_file.touch()
                
    # Create top-level project files
    top_level_files = {
        "README.md": "# koot: Adaptive Security Organism\n\nModular, Information-Agnostic Secret Subsystem.",
        "requirements.txt": "# Core Dependencies\n# e.g., cryptography, liboqs-python",
        ".gitignore": "__pycache__/\n*.pyc\n.env\n*.vault",
        "koot/__init__.py": "__version__ = '0.1.0'\n"
    }

    for file_name, content in top_level_files.items():
        file_path = root_dir / file_name
        if not file_path.exists():
            with open(file_path, "w") as f:
                f.write(content)
            logging.info(f"Created file: {file_name}")

    logging.info("koot architectural skeleton successfully generated! Ready for Phase 1.1.")

if __name__ == "__main__":
    create_koot_structure()