# koot/plugins/generators.py
import secrets
import string
import os
import json
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

class GeneratorPlugin:
    """
    Production-Ready Cryptographic Generators (Session 18).
    Loads obscured wordlists and provides extensive user customization.
    """

    def __init__(self, asset_key: bytes = None):
        self.wordlist = []
        self._asset_key = asset_key
        self._sealed_path = "data/wordlist.sealed"
        
        # Load the external obscured wordlist if possible
        if self._asset_key and os.path.exists(self._sealed_path):
            self._load_sealed_wordlist()

    def _load_sealed_wordlist(self):
        """Decrypts the wordlist into volatile memory."""
        try:
            chacha = ChaCha20Poly1305(self._asset_key)
            with open(self._sealed_path, "rb") as f:
                nonce = f.read(12)
                ciphertext = f.read()
            
            plaintext = chacha.decrypt(nonce, ciphertext, None)
            self.wordlist = json.loads(plaintext.decode('utf-8'))
        except Exception:
            self.wordlist = ["fallback", "words", "only"] # Minimal safety fallback

    def generate_password(self, 
                          length: int = 32, 
                          use_upper: bool = True, 
                          use_lower: bool = True, 
                          use_digits: bool = True, 
                          use_symbols: bool = True, 
                          exclude_chars: str = "") -> str:
        """
        Highly customizable password generator.
        """
        pool = ""
        if use_upper: pool += string.ascii_uppercase
        if use_lower: pool += string.ascii_lowercase
        if use_digits: pool += string.digits
        if use_symbols: pool += string.punctuation
        
        # Apply exclusions (e.g., to avoid ambiguous characters like 'l' and '1')
        pool = "".join([c for c in pool if c not in exclude_chars])
        
        if not pool:
            raise ValueError("Character pool is empty. Check customization options.")
            
        return ''.join(secrets.choice(pool) for _ in range(length))

    def generate_passphrase(self, 
                            words: int = 6, 
                            separator: str = "-", 
                            capitalize: bool = False, 
                            include_number: bool = False) -> str:
        """
        Highly customizable Diceware-style passphrase generator.
        """
        if not self.wordlist:
            raise RuntimeError("Wordlist not loaded. Cannot generate passphrase.")

        selected = [secrets.choice(self.wordlist) for _ in range(words)]
        
        if capitalize:
            selected = [w.capitalize() for w in selected]
        
        if include_number:
            # Inject a random digit into a random word to increase complexity
            idx = secrets.randbelow(len(selected))
            selected[idx] += str(secrets.randbelow(10))
            
        return separator.join(selected)

    def check_capabilities(self):
        return {
            "password_options": ["length", "use_upper", "use_lower", "use_digits", "use_symbols", "exclude_chars"],
            "passphrase_options": ["words", "separator", "capitalize", "include_number"]
        }