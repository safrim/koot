import asyncio
import os
import json
import logging
from pathlib import Path
from typing import Dict, Any

from koot.core.bus.registry import AdaptiveRegistry
from koot.identity.ledger import ShadowLedger
from koot.identity.derivation.pipeline import EntropyPipeline

class LocalIPCGateway:
    """
    Local Subsystem Gateway using Unix Domain Sockets.
    Allows host applications to request vaulting services locally.
    """
    def __init__(self, socket_path: str = "/tmp/koot.sock", registry: AdaptiveRegistry = None):
        self.socket_path = socket_path
        self.registry = registry
        self.logger = logging.getLogger("koot.network.ipc")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Processes incoming IPC messages."""
        try:
            data = await reader.read(4096)
            if not data:
                return

            request = json.loads(data.decode())
            action = request.get("action")
            payload = request.get("payload", {})

            # Dispatching to bus / internal handlers
            response = await self._dispatch_to_bus(action, payload)

            writer.write(json.dumps(response).encode())
            await writer.drain()
        except Exception as e:
            self.logger.error(f"IPC Error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _dispatch_to_bus(self, action: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Routes the IPC request to the internal Registry Bus."""
        
        if action == "vault.unlock":
            password = payload.get("password")
            if not password:
                return {"status": "error", "message": "Password is required"}
            
            try:
                koot_home = Path.home() / ".koot"
                ledger_path = koot_home / "ledger.shadow"
                salt_path = koot_home / ".salt"

                if not salt_path.exists() or not ledger_path.exists():
                    return {"status": "error", "message": "Vault not initialized."}

                with open(salt_path, "rb") as f:
                    salt = f.read()

                pipeline = EntropyPipeline()
                
                # CRITICAL FIX: Do not manually hash or fetch hardware factors here.
                # Let the EntropyPipeline use its unified logic so it matches init_koot.py exactly.
                lock_status, raw_master_key = pipeline.derive_and_lock_key(password, salt=salt)

                # Validate the key against the Ledger
                ledger = ShadowLedger(str(ledger_path), raw_master_key)
                ledger._load_db()

                self.logger.info("Vault unlocked via AppRole (Machine + Password).")
                return {"status": "success", "message": "Vault unlocked successfully"}
                
            except ValueError as e:
                import traceback
                print(f"\n[CRITICAL VALUE ERROR CRASH]\n{traceback.format_exc()}\n")
                self.logger.warning("Failed unlock attempt: Invalid credentials or wrong machine.")
                return {"status": "error", "message": "Invalid Master Password or Hardware Signature"}
            except Exception as e:
                self.logger.error(f"Error unlocking vault: {e}")
                return {"status": "error", "message": f"Internal error: {e}"} 

        if action == "system.override":
            command = payload.get("command")
            token = payload.get("token")
            
            if command == "nuke":
                # Note: In a fully wired environment, the 'token' would be verified 
                # against the OverrideMatrix here before proceeding.
                
                koot_home = Path.home() / ".koot"
                ledger_path = koot_home / "ledger.shadow"
                salt_path = koot_home / ".salt"
                
                # 1. Cryptographically Shred Files
                for path in [ledger_path, salt_path]:
                    if path.exists():
                        try:
                            # Overwrite with random bytes before unlink to prevent forensic disk recovery
                            with open(path, "r+b") as f:
                                f.write(os.urandom(path.stat().st_size))
                            path.unlink()
                            self.logger.info(f"Shredded {path.name}")
                        except Exception as e:
                            self.logger.error(f"Failed to shred {path.name}: {e}")
                
                # 2. Wipe RAM from C-Enclave
                try:
                    pipeline = EntropyPipeline()
                    pipeline.go_cold()
                except Exception as e:
                    self.logger.error(f"Error flushing memory enclave: {e}")
                
                self.logger.critical("MANUAL OVERRIDE: Dead Man's Switch Triggered. Ledger shredded, RAM wiped.")
                return {"status": "success", "message": "System Nuked. Ledger destroyed and RAM wiped."}

        if not self.registry:
            return {"status": "error", "message": "Registry Bus not initialized"}
        
        # Fallback for other registry dispatch logic
        return {"status": "success", "received": action}

    async def start(self):
        """Starts the Unix Domain Socket server."""
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        server = await asyncio.start_unix_server(self.handle_client, path=self.socket_path)
        
        # Restrict permissions: only the owner should access the socket
        os.chmod(self.socket_path, 0o600)

        self.logger.info(f"Koot IPC Gateway started at {self.socket_path}")
        async with server:
            await server.serve_forever()