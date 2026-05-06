import secrets
from typing import List, Tuple

# We use the 13th Mersenne Prime (2^521 - 1) to define our finite field.
# This comfortably and securely encompasses 256-bit and 512-bit keys.
PRIME = 2**521 - 1

class ShamirEscrowPlugin:
    """
    Shamir's Secret Sharing (M-of-N Escrow) Plugin.
    Implements polynomial interpolation over a finite field (modulo a Mersenne prime)
    to split and reconstruct critical vault keys, mitigating single points of failure.
    """
    
    def _eval_at(self, poly: List[int], x: int) -> int:
        """Evaluates the polynomial at x modulo PRIME."""
        result = 0
        for coeff in reversed(poly):
            result = (result * x + coeff) % PRIME
        return result

    def split_key(self, secret_bytes: bytes, n: int, m: int) -> List[Tuple[int, bytes]]:
        """
        Divides a secret key into 'n' shares, requiring 'm' shares to reconstruct.
        """
        if m > n:
            raise ValueError("Threshold (m) cannot be greater than total shares (n).")
        
        secret_int = int.from_bytes(secret_bytes, byteorder='big')
        if secret_int >= PRIME:
            raise ValueError("Secret is too large for the chosen finite field.")

        # Coefficients: a_0 is the secret, a_1...a_{m-1} are cryptographically random
        poly = [secret_int] + [secrets.randbelow(PRIME) for _ in range(m - 1)]

        shares = []
        for i in range(1, n + 1):
            x = i
            y = self._eval_at(poly, x)
            # Convert y back to bytes (length 66 to cover 521 bits safely)
            shares.append((x, y.to_bytes(66, byteorder='big')))
            
        return shares

    def _extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Extended Euclidean Algorithm for modular inverse."""
        x0, x1, y0, y1 = 1, 0, 0, 1
        while b != 0:
            q, a, b = a // b, b, a % b
            x0, x1 = x1, x0 - q * x1
            y0, y1 = y1, y0 - q * y1
        return a, x0, y0

    def _mod_inverse(self, k: int, p: int) -> int:
        """Returns the modular inverse of k mod p."""
        k = k % p
        if k < 0:
            k += p
        gcd, x, y = self._extended_gcd(k, p)
        if gcd != 1:
            raise ValueError(f"No modular inverse for {k} mod {p}")
        return (x % p + p) % p

    def reconstruct_key(self, shares: List[Tuple[int, bytes]], expected_length: int = 32) -> bytes:
        if not shares:
            raise ValueError("No shares provided for reconstruction.")

        secret_int = 0
        for i, (x_i, y_bytes) in enumerate(shares):
            y_i = int.from_bytes(y_bytes, byteorder='big')
            numerator = 1
            denominator = 1

            for j, (x_j, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = (numerator * (-x_j)) % PRIME
                denominator = (denominator * (x_i - x_j)) % PRIME

            lagrange_poly = (numerator * self._mod_inverse(denominator, PRIME)) % PRIME
            secret_int = (PRIME + secret_int + (y_i * lagrange_poly)) % PRIME

        # --- UPDATED SECTION ---
        try:
            return secret_int.to_bytes(expected_length, byteorder='big')
        except OverflowError:
            # If the integer is too big to fit in the expected_length, 
            # it means the interpolation yielded a massive garbage number.
            raise ValueError("Reconstructed secret exceeds expected length. Threshold not met or shares invalid.") 