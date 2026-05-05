import asyncio
import json
import os
import pytest
from koot.network.ipc.server import LocalIPCGateway
from koot.core.bus.registry import AdaptiveRegistry

async def send_ipc_message(socket_path, message):
    """Helper to send a message to the IPC socket and get a response."""
    reader, writer = await asyncio.open_unix_connection(socket_path)
    
    writer.write(json.dumps(message).encode())
    await writer.drain()
    
    data = await reader.read(4096)
    writer.close()
    await writer.wait_closed()
    
    return json.loads(data.decode())

@pytest.mark.asyncio
async def test_ipc_ping_pong():
    """
    Verifies that the IPC Gateway can receive a message 
    and return a success status.
    """
    socket_path = "/tmp/koot_test.sock"
    registry = AdaptiveRegistry()
    gateway = LocalIPCGateway(socket_path=socket_path, registry=registry)

    # Start the server in the background
    server_task = asyncio.create_task(gateway.start())
    
    # Give the server a moment to start and create the socket file
    await asyncio.sleep(0.1)
    
    try:
        # 1. Test standard ping/action
        request = {
            "action": "crypto.encrypt",
            "payload": {"data": "secret_payload"}
        }
        
        response = await send_ipc_message(socket_path, request)
        
        assert response["status"] == "success"
        assert response["received"] == "crypto.encrypt"
        
        # 2. Verify File Permissions (Security Check)
        stats = os.stat(socket_path)
        # Ensure only the owner has read/write access (0o600)
        assert (stats.st_mode & 0o777) == 0o600
        
    finally:
        server_task.cancel()
        if os.path.exists(socket_path):
            os.remove(socket_path)

if __name__ == "__main__":
    asyncio.run(test_ipc_ping_pong())