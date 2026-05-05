import asyncio
import os
import json
import logging
from typing import Dict, Any
from koot.core.bus.registry import AdaptiveRegistry

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

            # Integration with the Registry Bus
            # Example: dispatching to a crypto or storage plugin
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
        if not self.registry:
            return {"status": "error", "message": "Registry Bus not initialized"}
        
        # Placeholder for registry dispatch logic
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