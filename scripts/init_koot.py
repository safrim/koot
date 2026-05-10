#!/usr/bin/env python3
import os
import sys
import logging
import getpass
import socket
from pathlib import Path
import argon2.low_level

# Adjust path so script can find the nested 'koot' package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from koot.identity.ledger import ShadowLedger
from koot.identity.derivation.pipeline import EntropyPipeline
from koot.identity.machine.tpm_provider import TPMIdentityProvider
from koot.identity.machine.unlock import MachineUnlockManager

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("init_koot")

def main():
    print("=== Koot: Zero-Trust Vault Initialization ===")
    
    password = getpass.getpass("Enter New Master Password: ")
    confirm_password = getpass.getpass("Confirm Master Password: ")
    
    if password != confirm_password:
        logger.error("Passwords do not match. Aborting.")
        sys.exit(1)

    koot_home = Path.home() / ".koot"
    koot_home.mkdir(parents=True, exist_ok=True)
    
    ledger_path = koot_home / "ledger.shadow"
    salt_path = koot_home / ".salt"
    
    if ledger_path.exists() or salt_path.exists():
        logger.error("Vault already initialized. Wipe ~/.koot/ to start fresh.")
        sys.exit(1)

    logger.info("Generating cryptographic salt...")
    salt = os.urandom(16)
    with open(salt_path, "wb") as f:
        f.write(salt)

    logger.info("Anchoring identity to hardware factor...")
    tpm = TPMIdentityProvider()
    unlock_manager = MachineUnlockManager(tpm)
    machine_id = socket.gethostname()
    
    # 1. Generate the strict hardware factor based on TPM and Hostname
    hardware_factor = unlock_manager.generate_vault_key(machine_id, salt)

    pipeline = EntropyPipeline()

    logger.info("Deriving strictly bound mathematical key...")
    # 2. Strict Mathematical Binding matching the Server's logic exactly
    composite_secret = password.encode('utf-8') + hardware_factor
    raw_master_key = argon2.low_level.hash_secret_raw(
        secret=composite_secret,
        salt=salt,
        time_cost=pipeline.time_cost,
        memory_cost=pipeline.memory_cost,
        parallelism=pipeline.parallelism,
        hash_len=pipeline.hash_len,
        type=argon2.low_level.Type.ID
    )

    logger.info("Birthing the Shadow Ledger...")
    # 3. Because the new Ledger is stateful, simply instantiating it here 
    # will automatically trigger its internal _initialize_db() method, 
    # securely formatting the AES-GCM disk file with the {"secrets": {}} layout.
    ledger = ShadowLedger(str(ledger_path), raw_master_key)

    logger.info("Locking the Enclave in volatile memory...")
    pipeline.derive_and_lock_key(password, salt=salt, hardware_factor=hardware_factor)
        
    logger.info("[SUCCESS] Zero-Trust System Bootstrapped.")

if __name__ == "__main__":
    main()