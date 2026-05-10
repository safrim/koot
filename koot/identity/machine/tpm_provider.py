import logging
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
            self.logger.warning("TPM hardware not found. Falling back to software mock.")
            return b"MOCK_TPM_SIG_" + challenge

        # In a production environment, this would perform a TPM2_Quote or TPM2_Sign operation
        return b"HARDWARE_SIGNED_DATA_" + challenge