# tests/tier_1/test_mtls_gateway.py
import asyncio
import ssl
import logging
import pytest
from unittest.mock import MagicMock
from koot.network.gateway.mtls_server import ZeroTrustGateway

logging.basicConfig(level=logging.INFO)

HOST = '127.0.0.1'
PORT = 8888

CA_CERT = 'certs/ca.crt'
SERVER_CERT = 'certs/server.crt'
SERVER_KEY = 'certs/server.key'
CLIENT_CERT = 'certs/client.crt'
CLIENT_KEY = 'certs/client.key'
ROGUE_CLIENT_CERT = 'certs/rogue_client.crt'
ROGUE_CLIENT_KEY = 'certs/rogue_client.key'

@pytest.fixture
def mock_ledger():
    ledger = MagicMock()
    # By default, allow access for a standard user mock
    ledger.get_tenant.return_value = {
        "tenant_id": "Operative_Alpha",
        "permissions": ["READ", "WRITE"],
        "locked": False
    }
    return ledger

@pytest.fixture
async def mtls_server(mock_ledger):
    gateway = ZeroTrustGateway(HOST, PORT, CA_CERT, SERVER_CERT, SERVER_KEY, shadow_ledger=mock_ledger)
    task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.5)
    yield gateway, mock_ledger
    task.cancel()
    
@pytest.mark.asyncio
async def test_authorized_and_registered_client_success(mtls_server):
    """Test that a CA-signed cert that IS registered in the Shadow Ledger is granted access."""
    gateway, mock_ledger = mtls_server
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False 

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
    
    writer.write(b"Hello Vault")
    await writer.drain()
    
    response = await reader.read(1024)
    assert b"Acknowledged payload from 'Operative_Alpha'" in response
    
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
async def test_unregistered_client_rejection(mtls_server):
    """Test that a CA-signed cert that IS NOT in the Shadow Ledger gets dropped."""
    gateway, mock_ledger = mtls_server
    # Simulate the ledger not finding the cert hash
    mock_ledger.get_tenant.return_value = None 
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False 

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
    writer.write(b"Hello Vault")
    await writer.drain()
    
    response = await reader.read(1024)
    # The server should drop the connection immediately, resulting in an empty EOF read
    assert response == b"", "Breach! Server responded to unregistered sub-user."

@pytest.mark.asyncio
async def test_locked_client_rejection(mtls_server):
    """Test that a locked sub-user is actively dropped despite having a valid cert."""
    gateway, mock_ledger = mtls_server
    mock_ledger.get_tenant.return_value = {
        "tenant_id": "Operative_Alpha",
        "permissions": ["READ", "WRITE"],
        "locked": True # Locked status
    }
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False 

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
    writer.write(b"Hello Vault")
    await writer.drain()
    
    response = await reader.read(1024)
    assert response == b"", "Breach! Server responded to a LOCKED sub-user."