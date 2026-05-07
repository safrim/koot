import unittest
import os
from koot.plugins.export_engine.exporter import ExportEscrowPlugin

class MockBus:
    def dispatch(self, domain, action, payload):
        if action == "unvault_secret":
            return {
                "data": {
                    "uuid": payload["uuid"], 
                    "username": "testuser_koot", 
                    "password": "supersecret_koot"
                }
            }
        return None

class MockOverrideMatrix:
    def request_authorization(self, action, token):
        # Only allow if the explicit admin token is provided
        return token == "valid_admin_token"

class TestExportEngine(unittest.TestCase):
    def setUp(self):
        self.bus = MockBus()
        self.override_matrix = MockOverrideMatrix()
        self.exporter = ExportEscrowPlugin(self.bus, self.override_matrix)
        self.test_ids = ["uuid-alpha", "uuid-beta"]
        self.csv_path = "test_export_temp.csv"
        self.archive_path = "test_archive_temp.json"

    def test_csv_export_with_valid_override(self):
        # Tests that a valid admin token permits the plaintext CSV generation
        result = self.exporter.export_to_csv(self.test_ids, self.csv_path, "valid_admin_token")
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.csv_path))

    def test_csv_export_fails_without_override(self):
        # Tests that a missing or invalid token raises a PermissionError
        with self.assertRaises(PermissionError):
            self.exporter.export_to_csv(self.test_ids, self.csv_path, "invalid_token")

    def test_koot_archive_export(self):
        # Tests the standardized archive export format
        result = self.exporter.export_to_koot_archive(self.test_ids, self.archive_path)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.archive_path))

    def tearDown(self):
        # Cleanup temporary files
        if os.path.exists(self.csv_path):
            os.remove(self.csv_path)
        if os.path.exists(self.archive_path):
            os.remove(self.archive_path)

if __name__ == '__main__':
    unittest.main()