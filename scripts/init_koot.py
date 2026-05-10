#!/usr/bin/env python3
import os
import logging
import getpass
from pathlib import Path
from koot.identity.derivation.pipeline import EntropyPipeline
from koot.identity.ledger import ShadowLedger

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def initialize_cryptographic_core():
    """
    Phase 1, Session 1: The Birth Script.
    Focuses on Master Key derivation and Shadow Ledger initialization[cite: 5, 6, 21].
    """
    koot_home = Path.home() / ".koot"
    ledger_path = koot_home / "ledger.shadow"
    salt_path = koot_home / ".salt"

    # Ensure the configuration directory exists (security baseline) [cite: 6]
    koot_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    
    if ledger_path.exists():
        logging.warning(f"A Koot Ledger already exists at {ledger_path}.")
        confirm = input("Overwrite it? THIS WILL DESTROY ALL DATA! (y/N): ")
        if confirm.lower() != 'y':
            logging.info("Initialization aborted.")
            return

    # Securely collect the Master Password [cite: 5, 8]
    print("\n--- Koot: Cryptographic Birth (Secret Zero) ---")
    password = getpass.getpass("Set your Master Password: ")
    confirm_pwd = getpass.getpass("Confirm Master Password: ")

    if password != confirm_pwd:
        logging.error("Passwords do not match. Initialization failed.")
        return

    try:
        # Derive the Master Key using Argon2id via the Entropy Pipeline [cite: 5, 21, 33]
        pipeline = EntropyPipeline()
        salt = os.urandom(16)
        
        # We manually perform the initial derivation to get the raw key bytes 
        # specifically for sealing the ledger for the first time[cite: 21, 33].
        import argon2.low_level
        raw_master_key = argon2.low_level.hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=pipeline.time_cost,
            memory_cost=pipeline.memory_cost,
            parallelism=pipeline.parallelism,
            hash_len=pipeline.hash_len,
            type=argon2.low_level.Type.ID
        )

        # Initialize and save the Shadow Ledger [cite: 21, 33]
        # The ledger is protected by AES-GCM authenticated encryption[cite: 33].
        ledger = ShadowLedger(str(ledger_path), raw_master_key)
        
        # Store the salt needed for future derivation attempts [cite: 21]
        with open(salt_path, "wb") as f:
            f.write(salt)
        os.chmod(salt_path, 0o600)

        logging.info(f"Secret Zero born. Shadow Ledger sealed at {ledger_path}")
        logging.info("System is now ready for the Hardened CLI and IPC Handlers.")

    except Exception as e:
        logging.error(f"Failed to initialize Koot core: {e}")

if __name__ == "__main__":
    initialize_cryptographic_core()