import asyncio
import json
import os
import pytest
from koot.network.ipc.server import LocalIPCGateway
from koot.core.bus.registry import AdaptiveRegistry
from koot.cli.koot_cli import KootCLI

@pytest.mark.asyncio
async def test_cli_get_command():
    """
    Verifies that the CLI correctly formats and transmits a 'get' request
    to the IPC socket and correctly parses the response.
    """
    socket_path = "/tmp/koot_cli_test.sock"
    registry = AdaptiveRegistry()
    gateway = LocalIPCGateway(socket_path=socket_path, registry=registry)

    # Boot the core gateway in the background
    server_task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.1) # Wait for socket binding

    try:
        cli = KootCLI(socket_path=socket_path)
        
        # Simulate typing: `koot get 550e8400-e29b-41d4-a716-446655440000`
        response = await cli.send_command(action="vault.get", payload={"uuid": "12345678"})
        
        # Verify the headless core received and echoed the exact request
        assert response["status"] == "success"
        assert response["received"] == "vault.get"
        
    finally:
        server_task.cancel()
        if os.path.exists(socket_path):
            os.remove(socket_path)

@pytest.mark.asyncio
async def test_cli_nuke_command():
    """
    Verifies the extreme override command routing works as intended.
    """
    socket_path = "/tmp/koot_cli_test_nuke.sock"
    registry = AdaptiveRegistry()
    gateway = LocalIPCGateway(socket_path=socket_path, registry=registry)

    server_task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.1)

    try:
        cli = KootCLI(socket_path=socket_path)
        
        # Simulate typing: `koot override --nuke`
        response = await cli.send_command(action="system.override", payload={"command": "nuke"})
        
        assert response["status"] == "success"
        assert response["received"] == "system.override"
        
    finally:
        server_task.cancel()
        if os.path.exists(socket_path):
            os.remove(socket_path)