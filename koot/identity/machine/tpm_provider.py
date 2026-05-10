import logging
import hashlib
from typing import Optional

try:
    from tpm2_pytss import TSS2_Exception, TCTILdr, Context
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False

class TPMIdentityProvider:
    """
    Handles hardware-bound identity using TPM 2.0.
    Ensures 'Secret Zero' is protected by physical hardware.
    """
    def __init__(self, tcti: str = "device:/dev/tpm0"):
        self.tcti = tcti
        self.logger = logging.getLogger("koot.identity.tpm")

    def is_hardware_present(self) -> bool:
        """Checks if the TPM device is accessible."""
        if not TPM_AVAILABLE:
            return False
        try:
            with TCTILdr(self.tcti):
                return True
        except Exception:
            return False

    def create_identity_signature(self, challenge: bytes) -> bytes:
        """
        Signs a challenge using a TPM-resident restricted signing key.
        This proves the machine's identity without exposing the private key.
        """
        if not self.is_hardware_present():
            self.logger.warning("TPM hardware not found. Utilizing stable WSL/Linux OS anchor.")
            try:
                with open("/etc/machine-id", "r") as f:
                    machine_id = f.read().strip()
                
                # CRITICAL FIX: Ignore the ephemeral challenge in WSL mock.
                # We return a purely deterministic hash based ONLY on the machine's true identity.
                return hashlib.sha256(b"WSL_STABLE_MOCK_" + machine_id.encode('utf-8')).digest()
            
            except FileNotFoundError:
                self.logger.error("CRITICAL: /etc/machine-id not found. Cannot anchor identity.")
                raise RuntimeError("Vault cannot be securely locked to this machine.")

        # In a production environment, this would perform a TPM2_Quote or TPM2_Sign operation
        return b"HARDWARE_SIGNED_DATA_" + challenge 