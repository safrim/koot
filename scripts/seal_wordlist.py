# scripts/seal_wordlist.py
import json
import os
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def seal_assets(plaintext_list: list, key: bytes, output_path: str):
    """Obscures the wordlist using ChaCha20-Poly1305."""
    data = json.dumps(plaintext_list).encode('utf-8')
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, data, None)
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(nonce)
        f.write(ciphertext)

if __name__ == "__main__":
    # Example usage with a 32-byte dummy key
    test_key = b"01234567890123456789012345678901"
    words = ["apple", "banana", "cherry", "dragonfruit", "elderberry"]
    seal_assets(words, test_key, "data/wordlist.sealed")
    print("Wordlist sealed successfully.")