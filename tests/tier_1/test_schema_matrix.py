import unittest
from koot.core.schema.matrix import SchemaMatrix, SchemaState

class TestSchemaMatrix(unittest.TestCase):
    def setUp(self):
        self.matrix = SchemaMatrix()
        # Mock some schema mappings
        self.password_mapping = {"fields": ["username", "password"]}
        self.health_mapping = {"fields": ["blood_type", "allergies"]}
        self.legacy_mapping = {"fields": ["old_format_key"]}

    def test_opt_in_activation_and_manifest(self):
        self.matrix.plug_in("credentials.v1", self.password_mapping)
        self.matrix.plug_in("health.records", self.health_mapping)
        
        # Verify both are in the manifest
        manifest = self.matrix.get_queryable_manifest()
        self.assertIn("credentials.v1", manifest)
        self.assertIn("health.records", manifest)
        
        # Verify creation and reading are permitted
        self.assertTrue(self.matrix.validate_for_creation("credentials.v1"))
        self.assertTrue(self.matrix.validate_for_reading("credentials.v1"))

    def test_schema_tombstoning_countermeasure(self):
        # 1. Plug in a legacy schema
        self.matrix.plug_in("legacy.notes", self.legacy_mapping)
        
        # 2. Trigger the tombstone countermeasure
        self.matrix.unplug_to_tombstone("legacy.notes")
        
        # 3. Verify it is removed from the active manifest
        self.assertNotIn("legacy.notes", self.matrix.get_queryable_manifest())
        
        # 4. Verify Creation is strictly BLOCKED
        with self.assertRaises(PermissionError) as context:
            self.matrix.validate_for_creation("legacy.notes")
        self.assertIn("tombstoned", str(context.exception))
        
        # 5. Verify Reading/Decryption is still ALLOWED
        self.assertTrue(self.matrix.validate_for_reading("legacy.notes"))
        self.assertEqual(self.matrix.get_mapping("legacy.notes"), self.legacy_mapping)

    def test_strict_rejection_of_deactivated_and_unknown(self):
        self.matrix.plug_in("health.records", self.health_mapping)
        self.matrix.deactivate_schema("health.records")
        
        # Deactivated schemas should block both read and write
        with self.assertRaises(PermissionError):
            self.matrix.validate_for_creation("health.records")
        with self.assertRaises(PermissionError):
            self.matrix.validate_for_reading("health.records")
            
        # Unknown schemas should block both read and write
        with self.assertRaises(PermissionError):
            self.matrix.validate_for_creation("unknown.type")

if __name__ == '__main__':
    unittest.main()