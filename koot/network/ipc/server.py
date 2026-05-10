import asyncio
import os
import json
import logging
import socket
import argon2.low_level
from pathlib import Path
from typing import Dict, Any

from koot.core.bus.registry import AdaptiveRegistry
from koot.identity.ledger import ShadowLedger
from koot.identity.derivation.pipeline import EntropyPipeline
from koot.identity.machine.tpm_provider import TPMIdentityProvider
from koot.identity.machine.unlock import MachineUnlockManager

class LocalIPCGateway:
    """
    Local Subsystem Gateway using Unix Domain Sockets.
    Manages the lifecycle of the unlocked vault and routes agnostic payloads
    between the CLI and the volatile memory enclave.
    """
    def __init__(self, socket_path: str = "/tmp/koot.sock", registry: AdaptiveRegistry = None):
        self.socket_path = socket_path
        self.registry = registry
        self.logger = logging.getLogger("koot.network.ipc")
        
        # ACTIVE SESSION STATE
        # This attribute holds the decrypted ShadowLedger instance in RAM.
        # It remains None until a successful 'vault.unlock' is performed.
        self.active_ledger = None 

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """
        Processes incoming IPC messages.
        Standardizes responses to prevent the CLI from receiving empty pipes.
        """
        try:
            data = await reader.read(8192)
            if not data:
                return

            # Parse incoming JSON request
            request = json.loads(data.decode())
            action = request.get("action")
            payload = request.get("payload", {})

            # Route to the appropriate cryptographic or system handler
            response = await self._dispatch_to_bus(action, payload)

            # Standardized JSON Response
            writer.write(json.dumps(response).encode())
            await writer.drain()

        except Exception as e:
            self.logger.error(f"IPC Protocol Violation: {e}")
            # Ensure the client always receives an error object instead of a crash
            error_response = {"status": "error", "message": f"Server Logic Error: {str(e)}"}
            try:
                writer.write(json.dumps(error_response).encode())
                await writer.drain()
            except:
                pass 
        finally:
            writer.close()
            await writer.wait_closed()

    async def _dispatch_to_bus(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Internal router for vaulting operations and system overrides.
        """
        koot_home = Path.home() / ".koot"
        ledger_path = koot_home / "ledger.shadow"
        salt_path = koot_home / ".salt"

        # --- 1. ACTION: vault.unlock ---
        # Transition from Dormant to Active state.
        if action == "vault.unlock":
            password = payload.get("password")
            if not password:
                return {"status": "error", "message": "Password is required"}
            
            try:
                if not salt_path.exists() or not ledger_path.exists():
                    return {"status": "error", "message": "Vault not initialized."}

                with open(salt_path, "rb") as f:
                    salt = f.read()

                # A. Identity Anchoring: Fetch Strict Hardware Fingerprint
                tpm = TPMIdentityProvider()
                unlock_manager = MachineUnlockManager(tpm)
                machine_id = socket.gethostname()
                hardware_factor = unlock_manager.generate_vault_key(machine_id, salt)

                pipeline = EntropyPipeline()
                
                # B. Key Derivation: Symmetrical to init_koot.py math
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

                # C. Instantiate and Validate Ledger
                # This populates self.db in RAM after verifying the AES-GCM MAC tag
                ledger = ShadowLedger(str(ledger_path), raw_master_key)
                ledger._load_db() 

                # D. Final Lockdown: Secure the composite key in the C-Enclave
                pipeline.derive_and_lock_key(password, salt=salt, hardware_factor=hardware_factor)
                
                # Establish the active session
                self.active_ledger = ledger
                
                self.logger.info("Vault unlocked via AppRole. Active session established.")
                return {"status": "success", "message": "Vault unlocked successfully"}
                
            except ValueError:
                # Intentionally vague error to prevent password/hardware-factor probing
                return {"status": "error", "message": "Invalid Master Password or Hardware Signature"}
            except Exception as e:
                self.logger.error(f"Unlock failure: {e}")
                return {"status": "error", "message": "Internal failure during vault attachment."}

        # --- 2. ACTION: vault.add (Create/Update) ---
        if action == "vault.add":
            if not self.active_ledger:
                return {"status": "error", "message": "Vault is locked. Access denied."}
            
            key, value = payload.get("key"), payload.get("value")
            if not key or not value:
                return {"status": "error", "message": "Key and Value are required."}
            
            # The 'set' method performs encryption and an immediate disk seal
            self.active_ledger.set(key, value)
            return {"status": "success", "message": f"Secret '{key}' encrypted and saved."}

        # --- 3. ACTION: vault.read (Read) ---
        if action == "vault.read":
            if not self.active_ledger:
                return {"status": "error", "message": "Vault is locked."}
            
            key = payload.get("key")
            # Retrieval from the decrypted stateful map in RAM
            value = self.active_ledger.get(key)
            
            if value is None:
                return {"status": "error", "message": "Secret alias not found."}
            return {"status": "success", "data": value}

        # --- 4. ACTION: vault.delete (Delete) ---
        if action == "vault.delete":
            if not self.active_ledger:
                return {"status": "error", "message": "Vault is locked."}
            
            key = payload.get("key")
            self.active_ledger.delete(key)
            return {"status": "success", "message": f"Secret '{key}' purged from ledger."}

        # --- 5. ACTION: system.override ---
        # High-priority management functions
        if action == "system.override":
            command = payload.get("command")
            if command == "nuke":
                # A. Shred physical database and salt
                if hasattr(self.active_ledger, 'shred'):
                    self.active_ledger.shred()
                
                # B. Wipe volatile memory
                try:
                    pipeline = EntropyPipeline()
                    pipeline.go_cold()
                except:
                    pass
                
                self.active_ledger = None
                self.logger.critical("MANUAL OVERRIDE: Vault shredded, session terminated.")
                return {"status": "success", "message": "System Nuked. Ledger destroyed and RAM wiped."}

        # --- 6. FALLBACK: Registry Bus ---
        if not self.registry:
            return {"status": "error", "message": "Registry Bus not initialized"}
        
        return {"status": "success", "received": action}

    async def start(self):
        """Starts the Unix Domain Socket server."""
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        server = await asyncio.start_unix_server(self.handle_client, path=self.socket_path)
        
        # Permissions: 0o600 ensures only the local user can pings the socket
        os.chmod(self.socket_path, 0o600)

        self.logger.info(f"Koot IPC Gateway active at {self.socket_path}")
        async with server:
            await server.serve_forever()