import asyncio
import json
import os
import pytest
from pathlib import Path
import argon2.low_level

from koot.network.ipc.server import LocalIPCGateway
from koot.core.bus.registry import AdaptiveRegistry
from koot.identity.ledger import ShadowLedger
from koot.identity.derivation.pipeline import EntropyPipeline

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
    # Existing ping/pong check test
    socket_path = "/tmp/koot_test.sock"
    registry = AdaptiveRegistry()
    gateway = LocalIPCGateway(socket_path=socket_path, registry=registry)
    server_task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.1)
    try:
        request = {"action": "crypto.encrypt", "payload": {"data": "secret_payload"}}
        response = await send_ipc_message(socket_path, request)
        assert response["status"] == "success"
        stats = os.stat(socket_path)
        assert (stats.st_mode & 0o777) == 0o600
    finally:
        server_task.cancel()
        if os.path.exists(socket_path):
            os.remove(socket_path)

@pytest.mark.asyncio
async def test_vault_unlock_handler(tmp_path, monkeypatch):
    """
    Verifies that the vault.unlock IPC action correctly validates 
    passwords against the shadow ledger.
    """
    socket_path = str(tmp_path / "koot_unlock_test.sock")
    
    # Mock Path.home() so the server uses our tmp_path
    class MockPath:
        @staticmethod
        def home():
            return tmp_path

    monkeypatch.setattr("koot.network.ipc.server.Path", MockPath)
    
    # Manually initialize a test ledger in the tmp directory
    koot_home = tmp_path / ".koot"
    koot_home.mkdir(mode=0o700, parents=True)
    ledger_path = koot_home / "ledger.shadow"
    salt_path = koot_home / ".salt"
    
    salt = os.urandom(16)
    with open(salt_path, "wb") as f:
        f.write(salt)
        
    password = "test_super_secret"
    pipeline = EntropyPipeline()
    raw_master_key = argon2.low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=pipeline.time_cost,
        memory_cost=pipeline.memory_cost,
        parallelism=pipeline.parallelism,
        hash_len=pipeline.hash_len,
        type=argon2.low_level.Type.ID
    )
    
    # Saving initial ledger
    ledger = ShadowLedger(str(ledger_path), raw_master_key)
    
    registry = AdaptiveRegistry()
    gateway = LocalIPCGateway(socket_path=socket_path, registry=registry)
    server_task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.1)
    
    try:
        # Test 1: Empty password rejection
        req_empty = {"action": "vault.unlock", "payload": {}}
        res_empty = await send_ipc_message(socket_path, req_empty)
        assert res_empty["status"] == "error"
        assert "Password is required" in res_empty["message"]
        
        # Test 2: Wrong password rejection
        req_wrong = {"action": "vault.unlock", "payload": {"password": "wrong_password"}}
        res_wrong = await send_ipc_message(socket_path, req_wrong)
        assert res_wrong["status"] == "error"
        assert "Invalid Master Password" in res_wrong["message"]
        
        # Test 3: Correct password acceptance
        req_correct = {"action": "vault.unlock", "payload": {"password": password}}
        res_correct = await send_ipc_message(socket_path, req_correct)
        assert res_correct["status"] == "success"
        assert res_correct["message"] == "Vault unlocked successfully"
    finally:
        server_task.cancel()
        if os.path.exists(socket_path):
            os.remove(socket_path)