import asyncio
import json
import os
import pytest
from unittest.mock import patch
from koot.network.ipc.server import LocalIPCGateway
from koot.core.bus.registry import AdaptiveRegistry
from koot.cli.koot_cli import KootCLI, main

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

@patch("getpass.getpass", return_value="super_secret_master_password")
@patch("sys.argv", ["koot_cli.py", "unlock"])
@patch("koot.cli.koot_cli.KootCLI.send_command")
def test_cli_unlock_command_with_getpass(mock_send_command, mock_getpass):
    """
    Verifies that 'koot unlock' correctly prompts for a hidden password
    using getpass and passes it into the JSON payload.
    """
    # Mock the send_command to simulate a successful async response without booting the socket
    async def mock_response(*args, **kwargs):
        return {"status": "success", "received": "vault.unlock"}
    mock_send_command.side_effect = mock_response

    # Run the CLI main method
    main()

    # Verify getpass was called to hide the prompt
    mock_getpass.assert_called_once_with("Enter Master Password: ")
    
    # Verify the payload strictly contains the captured password
    mock_send_command.assert_called_once_with(
        "vault.unlock", 
        {"password": "super_secret_master_password"}
    )