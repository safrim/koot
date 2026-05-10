# tests/tier_1/test_mtls_gateway.py
import asyncio
import ssl
import logging
import pytest
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
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
# Removed the static ROGUE variables since we will generate them dynamically

@pytest.fixture
def ephemeral_rogue_cert(tmp_path):
    """Dynamically generates a rogue certificate and private key for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "intruder")])
    
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        subject # Self-signed, NOT signed by our production Root CA
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=1)
    ).sign(key, hashes.SHA256())

    key_path = tmp_path / "rogue.key"
    cert_path = tmp_path / "rogue.crt"

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    yield str(cert_path), str(key_path)

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
async def test_gateway_rejects_unauthorized_client(mtls_server, ephemeral_rogue_cert):
    """Test that a rogue certificate is rejected strictly at the TLS handshake level."""
    gateway, mock_ledger = mtls_server
    rogue_cert_path, rogue_key_path = ephemeral_rogue_cert
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=rogue_cert_path, keyfile=rogue_key_path)
    context.check_hostname = False 

    # We expect the connection to be forcibly reset or throw an SSL Error
    with pytest.raises((ssl.SSLError, ConnectionResetError, ssl.SSLEOFError, EOFError, OSError)):
        reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
        writer.write(b"Hello Vault")
        await writer.drain()
        
        data = await reader.read(1024)
        if not data:
            raise EOFError("Connection dropped by server")

@pytest.mark.asyncio
async def test_unregistered_client_rejection(mtls_server):
    """Test that a CA-signed cert that IS NOT in the Shadow Ledger gets dropped."""
    gateway, mock_ledger = mtls_server
    mock_ledger.get_tenant.return_value = None 
    
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=CA_CERT)
    context.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    context.check_hostname = False 

    reader, writer = await asyncio.open_connection(HOST, PORT, ssl=context)
    writer.write(b"Hello Vault")
    await writer.drain()
    
    response = await reader.read(1024)
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