from koot.identity.machine.tpm_provider import TPMIdentityProvider
from koot.identity.derivation.pipeline import EntropyPipeline

class MachineUnlockManager:
    def __init__(self, tpm_provider: TPMIdentityProvider):
        self.tpm = tpm_provider
        self.pipeline = EntropyPipeline()

    def generate_vault_key(self, machine_id: str, nonce: bytes) -> bytes:
        # 1. Get the hardware signature
        challenge = f"{machine_id}:{nonce.hex()}".encode()
        signature = self.tpm.create_identity_signature(challenge)

        # 2. Feed signature into Argon2id pipeline
        # FIX: Change 'password' to 'secret' and 'signature' to a string
        # FIX: Remove iterations and memory_kb as they are handled by the pipeline
        key, _ = self.pipeline.derive_key(
            secret=signature.hex(), 
            salt=nonce
        )
        return key 