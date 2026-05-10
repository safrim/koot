import os
import datetime
import ipaddress  # <-- Added this import
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_pem(data, path, is_key=False):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb"
    with open(path, mode) as f:
        f.write(data)
    if is_key:
        os.chmod(path, 0o600)  # Restrict access to private keys

def create_ca(ca_path, key_path):
    """Creates a self-signed Root CA."""
    key = generate_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "koot-root-ca"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(key, hashes.SHA256())

    save_pem(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), key_path, is_key=True)
    save_pem(cert.public_bytes(serialization.Encoding.PEM), ca_path)
    return cert, key

def create_signed_cert(ca_cert, ca_key, common_name, cert_path, key_path, is_server=False):
    """Generates a certificate signed by the Root CA."""
    key = generate_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    )

    if is_server:
        # KEY CHANGE: Using ipaddress object instead of raw bytes
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")) 
            ]),
            critical=False
        )

    cert = builder.sign(ca_key, hashes.SHA256())

    save_pem(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ), key_path, is_key=True)
    save_pem(cert.public_bytes(serialization.Encoding.PEM), cert_path)

if __name__ == "__main__":
    print("[*] Generating Koot mTLS Identity Infrastructure...")
    ca_c, ca_k = create_ca("certs/ca.crt", "certs/ca.key")
    print("[+] Created Root CA.")
    
    create_signed_cert(ca_c, ca_k, "localhost", "certs/server.crt", "certs/server.key", is_server=True)
    print("[+] Created Server Certificate (signed by CA).")
    
    create_signed_cert(ca_c, ca_k, "koot-cli-master", "certs/client.crt", "certs/client.key")
    print("[+] Created Master Client Certificate (signed by CA).")
    print("[!] Certificates deployed to ./certs/")