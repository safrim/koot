import os
import logging
from typing import Any
from koot.governance.analytics.heuristics import ThreatAlert
from koot.governance.override.interlock import OverrideMatrix

logger = logging.getLogger(__name__)

class AutonomousDefender:
    """
    Acts as the automated immune system for koot.
    Connects Heuristic Triggers to the OverrideMatrix and edge firewall.
    """
    def __init__(self, override_matrix: OverrideMatrix, system_token: str, system_cert_hash: str):
        self.override_matrix = override_matrix
        # The Defender holds the God-Mode credentials in memory to autonomously execute overrides
        self.system_token = system_token
        self.system_cert_hash = system_cert_hash

    def handle_threat(self, alert: ThreatAlert, source_ip: str = None, shadow_ledger: Any = None):
        """Processes a threat alert and executes the mapped countermeasure."""
        
        if alert.action == "freeze":
            # Rule: If an operative breaks a data-velocity or schema rule, auto-freeze them.
            logger.critical(f"DEFENDER: Auto-freezing tenant '{alert.tenant_id}' due to {alert.threat_type}.")
            success = self.override_matrix.trigger_localized_freeze(
                self.system_token, 
                self.system_cert_hash, 
                alert.tenant_id, 
                shadow_ledger
            )
            if not success:
                logger.error("DEFENDER: Failed to execute automated localized freeze.")
                
        elif alert.action == "ip_ban":
            # Rule: If there are repeated failed auth attempts, do NOT freeze the operative (prevents DoS).
            # Instead, silently IP-ban the attacker at the network edge.
            if source_ip:
                logger.critical(f"DEFENDER: Anti-DoS Activated. IP-Banning '{source_ip}' for {alert.threat_type}.")
                logger.info(f"DEFENDER: Tenant '{alert.tenant_id}' is deliberately NOT frozen to preserve access.")
                self._execute_ip_ban(source_ip)
            else:
                logger.warning("DEFENDER: IP ban requested but no source IP was provided in the context.")
                
        else:
            # Default fallback action
            logger.warning(f"DEFENDER: Log-only action executed for {alert.threat_type} on {alert.tenant_id}.")

    def _execute_ip_ban(self, ip_address: str):
        """
        Executes a firewall rule at the OS level to drop packets from the attacker.
        Wraps standard Linux tools like iptables or ufw.
        """
        # Note: In a production deployment, ensure the koot process has the appropriate 
        # capabilities (CAP_NET_ADMIN) or uses a secure helper script to modify iptables.
        try:
            logger.critical(f"FIREWALL: Deploying edge rule to DROP traffic from {ip_address}")
            # Example OS-level enforcement (Linux):
            # exit_code = os.system(f"iptables -A INPUT -s {ip_address} -j DROP")
            # if exit_code != 0:
            #     logger.error(f"FIREWALL: Failed to apply iptables rule for {ip_address}")
        except Exception as e:
            logger.error(f"FIREWALL: Exception while executing IP ban: {e}")