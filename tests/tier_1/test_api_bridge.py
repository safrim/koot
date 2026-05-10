import asyncio
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from koot.network.api.local_bridge import app, SOCKET_PATH
from koot.network.ipc.server import LocalIPCGateway
from koot.core.bus.registry import AdaptiveRegistry

@pytest_asyncio.fixture(autouse=True)
async def setup_background_ipc():
    registry = AdaptiveRegistry()
    gateway = LocalIPCGateway(socket_path=SOCKET_PATH, registry=registry)
    server_task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.1)
    yield
    server_task.cancel()
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)

@pytest.mark.asyncio
async def test_bridge_forwards_valid_request():
    payload = {
        "action": "ping.bus",
        "payload": {"check": "health"}
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/invoke", json=payload)
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["received"] == "ping.bus"

@pytest.mark.asyncio
async def test_bridge_handles_missing_core():
    if os.path.exists(SOCKET_PATH):
        os.remove(SOCKET_PATH)
        
    payload = {
        "action": "vault.unlock",
        "payload": {}
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post("/api/v1/invoke", json=payload)
    
    assert response.status_code == 503
    assert "socket not found" in response.json()["detail"]