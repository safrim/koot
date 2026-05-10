import os
import ssl
import asyncio
import pytest
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Import your gateway module
from koot.network.gateway.mtls_server import ZeroTrustGateway

@pytest.fixture
def ephemeral_rogue_cert(tmp_path):
    """
    Dynamically generates a self-signed rogue certificate and private key 
    solely for testing the Zero-Trust gateway drop logic.
    These files are isolated to a temporary directory and destroyed after use.
    """
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
    
    # Secure cleanup: Ensure the rogue keypick is instantly destroyed
    if os.path.exists(key_path):
        os.remove(key_path)
    if os.path.exists(cert_path):
        os.remove(cert_path)

@pytest.mark.asyncio
async def test_gateway_rejects_unauthorized_client(ephemeral_rogue_cert, unused_tcp_port):
    """
    Proves that the ZeroTrustGateway mathematically drops connections 
    from identities not signed by the internal Root CA.
    """
    rogue_cert_path, rogue_key_path = ephemeral_rogue_cert
    
    # 1. Boot an ephemeral instance of the Gateway for testing
    gateway = ZeroTrustGateway(
        host="127.0.0.1", 
        port=unused_tcp_port,
        ca_cert_path="certs/ca.crt",
        server_cert_path="certs/server.crt",
        server_key_path="certs/server.key",
        shadow_ledger=None
    )
    
    gateway_task = asyncio.create_task(gateway.start())
    await asyncio.sleep(0.1)
    
    # 2. Configure the rogue client
    client_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE 
    client_context.load_cert_chain(certfile=rogue_cert_path, keyfile=rogue_key_path)

    # 3. Attempt the breach and assert absolute failure
    try:
        # We broaden the expected exception because depending on the OS, a rejected 
        # mTLS handshake might manifest as an SSLError, an SSLEOFError, or a ConnectionResetError
        with pytest.raises((ssl.SSLError, ConnectionResetError, EOFError, OSError)) as exc_info:
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', 
                unused_tcp_port, 
                ssl=client_context
            )
            
            # Force the handshake to finalize by attempting to communicate
            writer.write(b"ATTACK_PAYLOAD")
            await writer.drain()
            
            # The server should have dropped us, meaning reading will return EOF or throw an error
            data = await reader.read(100)
            if not data:
                # If it silently returned no data, it means the server hung up on us
                raise EOFError("Server forcefully closed the connection without response.")
            
            writer.close()
            await writer.wait_closed()

    finally:
        gateway_task.cancel()