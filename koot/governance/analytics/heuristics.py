import json
import os
from pathlib import Path
from typing import Dict, Any, List

class ThreatAlert(Exception):
    """Custom exception raised when a heuristic baseline is breached."""
    def __init__(self, tenant_id: str, threat_type: str, details: str, action: str):
        super().__init__(f"THREAT [{threat_type}] for {tenant_id}: {details}")
        self.tenant_id = tenant_id
        self.threat_type = threat_type
        self.details = details
        self.action = action

class HeuristicEvaluator:
    def __init__(self, manifest_path: str = None):
        if manifest_path is None:
            # Default to the config folder outside the logic directory
            base_dir = Path(__file__).resolve().parent.parent.parent.parent
            self.manifest_path = base_dir / "config" / "heuristics_manifest.json"
        else:
            self.manifest_path = Path(manifest_path)
            
        self.manifest = self._load_manifest()
        self.baselines = self.manifest.get("baselines", {})
        self.threats = self.manifest.get("threats", {})

    def _load_manifest(self) -> Dict[str, Any]:
        """Dynamically loads the JSON Rule Manifest."""
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Heuristics manifest not found at {self.manifest_path}")
        with open(self.manifest_path, 'r') as f:
            return json.load(f)

    def reload_rules(self):
        """Allows hot-swapping of rules without restarting the server."""
        self.manifest = self._load_manifest()
        self.baselines = self.manifest.get("baselines", {})
        self.threats = self.manifest.get("threats", {})

    def evaluate_tenant_metrics(self, tenant_id: str, current_metrics: Dict[str, Any]) -> List[ThreatAlert]:
        """
        Evaluates real-time metrics against the loaded baselines.
        Returns a list of ThreatAlert objects if anomalies are detected.
        """
        alerts = []
        
        # Check Velocity Baseline
        download_velocity = current_metrics.get("download_velocity_mb_hr", 0)
        max_velocity = self.baselines.get("max_download_velocity_mb_hr", float('inf'))
        if download_velocity > max_velocity:
            threat = self.threats.get("MASS_DOWNLOAD", {})
            alerts.append(ThreatAlert(
                tenant_id=tenant_id,
                threat_type="MASS_DOWNLOAD",
                details=f"Velocity {download_velocity}MB/hr exceeds limit of {max_velocity}MB/hr.",
                action=threat.get("action", "log")
            ))

        # Check Schema Violations
        illegal_schema_attempts = current_metrics.get("illegal_schema_attempts", 0)
        max_illegal_schema = self.baselines.get("max_illegal_schema_attempts", 3)
        if illegal_schema_attempts >= max_illegal_schema:
            threat = self.threats.get("SCHEMA_VIOLATION", {})
            alerts.append(ThreatAlert(
                tenant_id=tenant_id,
                threat_type="SCHEMA_VIOLATION",
                details=f"{illegal_schema_attempts} illegal schema accesses attempted.",
                action=threat.get("action", "log")
            ))

        # Check Authentication Failures
        failed_auth_attempts = current_metrics.get("failed_auth_attempts", 0)
        max_failed_auth = self.baselines.get("max_failed_auth_attempts", 5)
        if failed_auth_attempts >= max_failed_auth:
            threat = self.threats.get("BRUTE_FORCE_OR_STOLEN_CERT", {})
            alerts.append(ThreatAlert(
                tenant_id=tenant_id,
                threat_type="BRUTE_FORCE_OR_STOLEN_CERT",
                details=f"{failed_auth_attempts} failed auth attempts.",
                action=threat.get("action", "log")
            ))

        return alerts