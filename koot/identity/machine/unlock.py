from koot.identity.machine.tpm_provider import TPMIdentityProvider
from koot.identity.derivation.pipeline import EntropyPipeline

class MachineUnlockManager:
    """
    Orchestrates machine-bound key generation by bridging the 
    TPM Identity Provider and the Entropy Pipeline.
    """
    def __init__(self, tpm_provider: TPMIdentityProvider):
        self.tpm = tpm_provider
        self.pipeline = EntropyPipeline()

    def generate_vault_key(self, machine_id: str, nonce: bytes) -> bytes:
        """
        Generates a 256-bit key derived strictly from the machine's 
        hardware identity and a provided nonce.
        """
        # 1. Get the hardware signature (Machine Identity)
        challenge = f"{machine_id}:{nonce.hex()}".encode()
        signature = self.tpm.create_identity_signature(challenge)

        # 2. Feed signature into Argon2id pipeline for deterministic key derivation
        key, _ = self.pipeline.derive_key(
            secret=signature.hex(), 
            salt=nonce
        )
        return key