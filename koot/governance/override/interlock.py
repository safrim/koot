import threading
import secrets
import logging
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)

class OverrideMatrix:
    """
    High-priority command interface for manual system overrides.
    Requires both the Admin Token AND the Master Certificate Hash
    to execute critical halts or aborts. Sub-user contexts are silently ignored.
    """
    def __init__(self, admin_token: str, master_cert_hash: str):
        self._admin_token = admin_token
        self._master_cert_hash = master_cert_hash
        self._is_halted = False
        self._lock = threading.Lock() 
        
        self._abort_callbacks: list[Callable] = []
        self._freeze_callbacks: list[Callable[[str], None]] = []

    def verify_master_authority(self, token: str, client_cert_hash: str) -> bool:
        """Strictly validates both the token and the certificate hash."""
        # Use compare_digest for both to mitigate timing attacks
        valid_token = secrets.compare_digest(self._admin_token, token)
        valid_cert = secrets.compare_digest(self._master_cert_hash, client_cert_hash)
        
        return valid_token and valid_cert

    def trigger_global_halt(self, token: str, client_cert_hash: str) -> bool:
        """Instantly sets the system to a halted state."""
        if not self.verify_master_authority(token, client_cert_hash):
            # Silently drop unauthorized requests to mask defensive behavior
            logger.warning("Unauthorized override attempt. Silently dropping.")
            return False
        
        with self._lock:
            self._is_halted = True
            logger.critical("MANUAL OVERRIDE: Global system halt engaged.")
            return True

    def register_abort_callback(self, callback: Callable):
        """Register functions to call when a manual abort is triggered."""
        self._abort_callbacks.append(callback)

    def trigger_abort_all(self, token: str, client_cert_hash: str) -> bool:
        """Executes all registered abort sequences (e.g., stopping a Nuke)."""
        if not self.verify_master_authority(token, client_cert_hash):
            return False
            
        logger.info("MANUAL OVERRIDE: Executing all registered abort sequences.")
        for callback in self._abort_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error(f"Abort callback failed: {e}")
        return True

    def register_freeze_callback(self, callback: Callable[[str], None]):
        """Register functions to call when a localized freeze is triggered."""
        self._freeze_callbacks.append(callback)

    def trigger_localized_freeze(self, token: str, client_cert_hash: str, target_tenant_id: str, shadow_ledger: Any) -> bool:
        """Silently neutralizes a single user by locking the ledger and severing sockets."""
        if not self.verify_master_authority(token, client_cert_hash):
            logger.warning(f"Unauthorized localized freeze attempt on '{target_tenant_id}'. Silently dropping.")
            return False
        
        logger.critical(f"MANUAL OVERRIDE: Localized freeze engaged for tenant '{target_tenant_id}'.")
        
        # 1. Toggle locked=True in the Shadow Ledger
        if shadow_ledger:
            success = shadow_ledger.lock_tenant_by_id(target_tenant_id)
            if not success:
                logger.error(f"Failed to lock tenant '{target_tenant_id}' in ledger. Tenant not found.")
        
        # 2. Sever all active sockets via registered callbacks (e.g., connected to the Gateway)
        for callback in self._freeze_callbacks:
            try:
                callback(target_tenant_id)
            except Exception as e:
                logger.error(f"Freeze callback failed for tenant '{target_tenant_id}': {e}")
                
        return True

    def provision_agent(self, token: str, client_cert_hash: str, tenant_id: str, permissions: list, shadow_ledger: Any, entropy_pipeline: Any, core_master_key: bytes, new_client_cert_hash: str = None, packager: Any = None) -> dict:
        """
        Autonomously generates an escrowed sub-key and injects the new user into the Shadow Ledger.
        If a packager is provided, it handles cert generation and outputs an encrypted onboarding zip.
        """
        if not self.verify_master_authority(token, client_cert_hash):
            logger.warning(f"Unauthorized provisioning attempt for '{tenant_id}'. Silently dropping.")
            return {"success": False}
        
        logger.info(f"MANUAL OVERRIDE: Provisioning new agent '{tenant_id}'.")
        
        try:
            # 1. Generate the true mathematically random 256-bit tenant master key
            tenant_key = entropy_pipeline.generate_tenant_master_key()
            
            # 2. Wrap it cryptographically with the core Master Key for escrow
            escrowed_key = entropy_pipeline.wrap_for_escrow(tenant_key, core_master_key)
            
            otp = None
            encrypted_package = None

            # Generate onboarding package if packager is provided
            if packager:
                otp = packager.generate_otp()
                encrypted_package, generated_cert_hash = packager.create_encrypted_package(tenant_id, otp)
                new_client_cert_hash = generated_cert_hash
            elif not new_client_cert_hash:
                raise ValueError("Must provide either 'new_client_cert_hash' or a 'packager'.")

            # 3. Inject the new operative into the stealth ledger
            if shadow_ledger:
                shadow_ledger.add_tenant(
                    cert_hash=new_client_cert_hash,
                    tenant_id=tenant_id,
                    permissions=permissions,
                    escrowed_key=escrowed_key
                )
                
            return {
                "success": True,
                "tenant_id": tenant_id,
                "cert_hash": new_client_cert_hash,
                "otp": otp,
                "encrypted_package": encrypted_package
            }
        except Exception as e:
            logger.error(f"Failed to provision agent '{tenant_id}': {e}")
            return {"success": False}

    @property
    def is_halted(self) -> bool:
        with self._lock: 
            return self._is_halted

    def reset_halt(self, token: str, client_cert_hash: str) -> bool:
        """Resets the halt state."""
        if self.verify_master_authority(token, client_cert_hash):
            with self._lock: 
                self._is_halted = False
            return True
        return False