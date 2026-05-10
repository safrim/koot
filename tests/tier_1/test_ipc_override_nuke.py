import pytest
import asyncio
import os
from pathlib import Path
from koot.network.ipc.server import LocalIPCGateway

@pytest.mark.asyncio
async def test_ipc_nuke_command(tmp_path, monkeypatch):
    # 1. Setup mock koot home and files
    koot_home = tmp_path / ".koot"
    koot_home.mkdir()
    ledger_path = koot_home / "ledger.shadow"
    salt_path = koot_home / ".salt"
    
    # Write dummy data to simulate a live vault
    ledger_path.write_bytes(b"dummy_ledger_data_for_shredding_test")
    salt_path.write_bytes(b"dummy_salt_data")
    
    # Mock Path.home() to point to our isolated tmp_path
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    
    # 2. Setup the IPC Gateway
    gateway = LocalIPCGateway(socket_path=str(tmp_path / "koot.sock"))
    
    # 3. Dispatch the Nuke command payload
    payload = {
        "command": "nuke", 
        "token": "dummy_admin_token"
    }
    response = await gateway._dispatch_to_bus("system.override", payload)
    
    # 4. Verify outcomes
    assert response["status"] == "success"
    assert "Ledger destroyed and RAM wiped" in response["message"]
    
    # Ensure files are completely missing from the filesystem
    assert not ledger_path.exists(), "Ledger file was not shredded"
    assert not salt_path.exists(), "Salt file was not shredded"