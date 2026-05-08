import os
import io
import json
import secrets
import zipfile
import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography import x509

class SecureOnboardingPackager:
    """
    Generates client certificates and connection parameters, packaging them into
    an AES-GCM encrypted payload locked by a 6-digit OTP for secure out-of-band handoff.
    """
    def __init__(self, server_ip: str, gateway_port: int):
        self.server_ip = server_ip
        self.gateway_port = gateway_port

    def generate_otp(self) -> str:
        """Generates a secure 6-digit One-Time PIN."""
        return f"{secrets.randbelow(1000000):06d}"

    def generate_client_certificate(self, tenant_id: str) -> tuple[bytes, bytes, str]:
        """Generates an X.509 certificate and private key for the tenant."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, tenant_id),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(private_key, hashes.SHA256())

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Calculate cert hash for the Shadow Ledger
        digest = hashes.Hash(hashes.SHA256())
        digest.update(cert_pem)
        cert_hash_hex = digest.finalize().hex()

        return cert_pem, key_pem, cert_hash_hex

    def create_encrypted_package(self, tenant_id: str, otp: str) -> tuple[bytes, str]:
        """Creates the connection package and encrypts it using the OTP."""
        cert_pem, key_pem, cert_hash_hex = self.generate_client_certificate(tenant_id)

        config = {
            "server_ip": self.server_ip,
            "gateway_port": self.gateway_port,
            "tenant_id": tenant_id
        }

        # Create an in-memory zip payload
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr("client.crt", cert_pem)
            zip_file.writestr("client.key", key_pem)
            zip_file.writestr("connection.json", json.dumps(config, indent=4))
        
        payload = zip_buffer.getvalue()

        # Stretch the 6-digit OTP into a 256-bit AES key
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000, # High iteration count counters brute-forcing the 6-digit PIN
        )
        derived_key = kdf.derive(otp.encode('utf-8'))

        # Encrypt with AES-GCM
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)

        # Prepend salt and nonce so the client can decrypt it
        encrypted_package = salt + nonce + ciphertext

        return encrypted_package, cert_hash_hex