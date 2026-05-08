import pytest
from unittest.mock import MagicMock
from koot.governance.analytics.heuristics import ThreatAlert
from koot.governance.analytics.defender import AutonomousDefender
from koot.governance.override.interlock import OverrideMatrix

def test_autonomous_freeze_on_velocity_breach():
    # Setup
    mock_matrix = MagicMock(spec=OverrideMatrix)
    mock_matrix.trigger_localized_freeze.return_value = True
    mock_ledger = MagicMock()
    
    defender = AutonomousDefender(
        override_matrix=mock_matrix,
        system_token="fake_admin_token",
        system_cert_hash="fake_cert_hash"
    )
    
    # Simulate a Mass Download alert (which should have action="freeze")
    alert = ThreatAlert(
        tenant_id="Operative_Alpha",
        threat_type="MASS_DOWNLOAD",
        details="Velocity 600MB/hr exceeds limit.",
        action="freeze"
    )
    
    # Execute
    defender.handle_threat(alert, source_ip="192.168.1.50", shadow_ledger=mock_ledger)
    
    # Verify the freeze was called with God-Mode credentials
    mock_matrix.trigger_localized_freeze.assert_called_once_with(
        "fake_admin_token", 
        "fake_cert_hash", 
        "Operative_Alpha", 
        mock_ledger
    )

def test_anti_dos_ip_ban_preserves_tenant():
    # Setup
    mock_matrix = MagicMock(spec=OverrideMatrix)
    defender = AutonomousDefender(
        override_matrix=mock_matrix,
        system_token="fake_admin_token",
        system_cert_hash="fake_cert_hash"
    )
    
    # Spy on the internal IP ban method
    defender._execute_ip_ban = MagicMock()
    
    # Simulate a Brute Force alert (which should have action="ip_ban")
    alert = ThreatAlert(
        tenant_id="Operative_Beta",
        threat_type="BRUTE_FORCE_OR_STOLEN_CERT",
        details="5 failed auth attempts.",
        action="ip_ban"
    )
    
    # Execute
    defender.handle_threat(alert, source_ip="203.0.113.42")
    
    # Verify the localized freeze was NEVER called (Anti-DoS protection)
    mock_matrix.trigger_localized_freeze.assert_not_called()
    
    # Verify the IP ban was executed against the attacker
    defender._execute_ip_ban.assert_called_once_with("203.0.113.42")

def test_missing_ip_on_ban_action():
    # Ensure system doesn't crash if IP is missing during a ban request
    mock_matrix = MagicMock(spec=OverrideMatrix)
    defender = AutonomousDefender(mock_matrix, "token", "hash")
    defender._execute_ip_ban = MagicMock()
    
    alert = ThreatAlert("Operative_Gamma", "BRUTE_FORCE", "details", "ip_ban")
    
    # Execute without source_ip
    defender.handle_threat(alert, source_ip=None)
    
    # Ensure neither freeze nor ban occurred, but no exception was raised
    mock_matrix.trigger_localized_freeze.assert_not_called()
    defender._execute_ip_ban.assert_not_called()