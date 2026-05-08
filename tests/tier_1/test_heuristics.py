import unittest
import json
import tempfile
import os
from pathlib import Path
from koot.governance.analytics.heuristics import HeuristicEvaluator, ThreatAlert

class TestHeuristicsEvaluator(unittest.TestCase):
    def setUp(self):
        # Create a temporary manifest for testing to prevent altering production config
        self.test_manifest = {
            "version": "1.0",
            "baselines": {
                "max_download_velocity_mb_hr": 100,
                "max_illegal_schema_attempts": 3
            },
            "threats": {
                "MASS_DOWNLOAD": {"action": "trigger_localized_freeze"},
                "SCHEMA_VIOLATION": {"action": "trigger_localized_freeze"}
            }
        }
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        json.dump(self.test_manifest, self.temp_file)
        self.temp_file.close()
        
        self.evaluator = HeuristicEvaluator(manifest_path=self.temp_file.name)

    def tearDown(self):
        os.remove(self.temp_file.name)

    def test_normal_metrics_pass(self):
        """Ensure standard metrics do not trigger false positives."""
        metrics = {
            "download_velocity_mb_hr": 50,
            "illegal_schema_attempts": 0
        }
        alerts = self.evaluator.evaluate_tenant_metrics("Operative_Alpha", metrics)
        self.assertEqual(len(alerts), 0)

    def test_mass_download_trigger(self):
        """Ensure exceeding download velocity triggers MASS_DOWNLOAD threat."""
        metrics = {
            "download_velocity_mb_hr": 150, # Exceeds 100
            "illegal_schema_attempts": 0
        }
        alerts = self.evaluator.evaluate_tenant_metrics("Operative_Beta", metrics)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].threat_type, "MASS_DOWNLOAD")
        self.assertEqual(alerts[0].action, "trigger_localized_freeze")

    def test_schema_violation_trigger(self):
        """Ensure hitting schema limits triggers SCHEMA_VIOLATION threat."""
        metrics = {
            "download_velocity_mb_hr": 10,
            "illegal_schema_attempts": 3 # Hits limit of 3
        }
        alerts = self.evaluator.evaluate_tenant_metrics("Operative_Gamma", metrics)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].threat_type, "SCHEMA_VIOLATION")

    def test_hot_swap_reload(self):
        """Ensure the evaluator can reload rules from disk during runtime."""
        # Update manifest on disk
        self.test_manifest["baselines"]["max_download_velocity_mb_hr"] = 500
        with open(self.temp_file.name, 'w') as f:
            json.dump(self.test_manifest, f)
            
        # Hot reload
        self.evaluator.reload_rules()
        
        # Test that old triggering metrics now pass
        metrics = {"download_velocity_mb_hr": 150}
        alerts = self.evaluator.evaluate_tenant_metrics("Operative_Alpha", metrics)
        self.assertEqual(len(alerts), 0) # Should now pass because limit is 500

if __name__ == '__main__':
    unittest.main()