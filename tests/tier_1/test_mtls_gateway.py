# tests/tier_1/test_mtls_gateway.py
import asyncio
import ssl
import logging
import pytest
from koot.network.gateway.mtls_server import ZeroTrustGateway

# Disable verbose logging for tests unless debugging
logging.basicConfig(level=logging.INFO)

HOST = '127.0.0.1'
PORT = 8888

# Assuming certs are generated in a 'certs' folder at the root
CA_CERT = 'certs/ca.crt'
SERVER_CERT = 'certs/server.crt'
SERVER_KEY = 'certs/server.key'
CLIENT_CERT = 'certs/client.crt'
CLIENT_KEY = 'certs/client.key'
ROGUE_CLIENT_CERT = 'certs/rogue_client.crt'
ROGUE_CLIENT_KEY = 'certs/rogue_client.key'

@pytest.fixture
async def mtls_server():
    gateway = ZeroTrustGateway(HOST, PORT, CA_CERT, SERVER_CERT, SERVER_KEY)
    task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.5) # Allow server to bind
    yield
    task.cancel()
    
@pytest.mark.asyncio
async def test_authorized_client_success(mtls_server):
    """Test that a client with a valid CA-signed certificate is granted access."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False # Bypass hostname check for local testing

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
    
    writer.write(b"Hello Vault")
    await writer.drain()
    
    response = await reader.read(1024)
    assert b"Acknowledged payload" in response
    
    writer.close()
    await writer.wait_closed()

@pytest.mark.asyncio
async def test_unauthorized_client_rejection(mtls_server):
    """Test that a client lacking a valid cert is violently dropped at the TLS handshake."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    # Loading the ROGUE client cert (signed by an unknown CA)
    context.load_cert_chain(certfile=ROGUE_CLIENT_CERT, keyfile=ROGUE_CLIENT_KEY)
    context.check_hostname = False

    try:
        reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
        
        writer.write(b"Hello Vault")
        await writer.drain()
        response = await reader.read(1024)
        
        # If no exception was thrown, the server must have severed the pipe, 
        # resulting in an empty read (EOF).
        assert response == b"", f"Security Breach! Server responded to rogue client: {response}"
        
    except (ssl.SSLError, ConnectionResetError, EOFError):
        # If the OS/Python threw a hard error, the rejection also worked perfectly.
        pass

@pytest.mark.asyncio
async def test_no_cert_client_rejection(mtls_server):
    """Test that a standard TLS client (no client cert) is dropped."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.check_hostname = False

    try:
        reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
        
        writer.write(b"Hello Vault")
        await writer.drain()
        response = await reader.read(1024)
        
        assert response == b"", f"Security Breach! Server responded to unauthenticated client: {response}"
        
    except (ssl.SSLError, ConnectionResetError, EOFError):
        pass