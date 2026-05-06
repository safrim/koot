import pytest
import os
from koot.plugins.shamir_escrow import ShamirEscrowPlugin
from koot.core.bus.contracts import ContractEnforcer

def test_shamir_contract_compliance():
    """Ensure the plugin complies with the Tier 1 Contract."""
    assert ContractEnforcer.verify_tier_1(ShamirEscrowPlugin, ["split_key", "reconstruct_key"])

def test_shamir_split_and_reconstruct():
    """Test 3-of-5 M-of-N escrow scenario."""
    plugin = ShamirEscrowPlugin()
    # Mocking a standard 256-bit AES or Kyber key
    original_secret = os.urandom(32)  

    # Split into 5 shares, requiring 3 to unlock
    shares = plugin.split_key(original_secret, n=5, m=3)

    assert len(shares) == 5

    # Reconstruct with exactly 3 shares (indices 0, 2, 4)
    subset_shares = [shares[0], shares[2], shares[4]]
    recovered_secret = plugin.reconstruct_key(subset_shares, expected_length=32)

    assert recovered_secret == original_secret

def test_shamir_insufficient_shares_fails():
    """Ensure reconstruction fails cleanly if threshold isn't met."""
    plugin = ShamirEscrowPlugin()
    original_secret = os.urandom(32)
    
    shares = plugin.split_key(original_secret, n=5, m=3)
    
    # Reconstruct with only 2 shares (below threshold)
    subset_shares = [shares[1], shares[3]]
    
    # The math will yield a 521-bit garbage integer, which won't fit in 32 bytes
    with pytest.raises(ValueError, match="exceeds expected length"):
        plugin.reconstruct_key(subset_shares, expected_length=32)

def test_shamir_invalid_threshold():
    """Ensure invalid parameters are rejected."""
    plugin = ShamirEscrowPlugin()
    original_secret = os.urandom(32)
    
    with pytest.raises(ValueError):
        # Threshold (m) cannot be greater than Total Shares (n)
        plugin.split_key(original_secret, n=3, m=5)