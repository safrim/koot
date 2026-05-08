import io
import zipfile
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from koot.identity.provisioning.packager import SecureOnboardingPackager

def test_secure_package_encryption_and_decryption():
    packager = SecureOnboardingPackager("192.168.1.100", 8443)
    otp = packager.generate_otp()
    
    assert len(otp) == 6
    assert otp.isdigit()
    
    # Generate the package
    encrypted_package, cert_hash = packager.create_encrypted_package("Operative_Gamma", otp)
    
    # Simulate client-side decryption
    salt = encrypted_package[:16]
    nonce = encrypted_package[16:28]
    ciphertext = encrypted_package[28:]
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    derived_key = kdf.derive(otp.encode('utf-8'))
    
    aesgcm = AESGCM(derived_key)
    decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
    
    # Unpack the decrypted zip buffer in memory to read the contents
    with zipfile.ZipFile(io.BytesIO(decrypted_payload), 'r') as zip_ref:
        # Verify the structure
        assert "client.crt" in zip_ref.namelist()
        assert "connection.json" in zip_ref.namelist()
        
        # Verify the actual injected configuration data
        connection_data = zip_ref.read("connection.json")
        assert b"192.168.1.100" in connection_data
        assert b"Operative_Gamma" in connection_data

def test_tamper_protection():
    packager = SecureOnboardingPackager("192.168.1.100", 8443)
    otp = "123456"
    encrypted_package, _ = packager.create_encrypted_package("Operative_Gamma", otp)
    
    # Tamper with the ciphertext byte
    tampered_package = bytearray(encrypted_package)
    tampered_package[-1] ^= 0x01 
    
    # Recast slices explicitly back to immutable bytes for the cryptography library
    salt = bytes(tampered_package[:16])
    nonce = bytes(tampered_package[16:28])
    ciphertext = bytes(tampered_package[28:])
    
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
    derived_key = kdf.derive(otp.encode('utf-8'))
    
    aesgcm = AESGCM(derived_key)
    
    # AES-GCM should throw an InvalidTag exception
    with pytest.raises(Exception):
        aesgcm.decrypt(nonce, ciphertext, None)