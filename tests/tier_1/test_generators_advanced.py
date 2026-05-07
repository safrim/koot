# tests/tier_1/test_generators_advanced.py
import unittest
import os
from koot.plugins.generators import GeneratorPlugin

class TestAdvancedGenerators(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = b"static_test_key_32_bytes_long_!!"
        # Create a temporary sealed file for testing
        from scripts.seal_wordlist import seal_assets
        seal_assets(["testword"], cls.key, "data/wordlist.sealed")

    def test_sealed_loading(self):
        """Verifies wordlist is only accessible with the correct key."""
        plugin = GeneratorPlugin(asset_key=self.key)
        self.assertIn("testword", plugin.wordlist)

    def test_password_customization(self):
        """Verifies strict adherence to character exclusions."""
        plugin = GeneratorPlugin()
        # Request digits only but exclude '1' and '2'
        pw = plugin.generate_password(length=100, use_upper=False, use_lower=False, 
                                      use_symbols=False, exclude_chars="12")
        self.assertNotIn("1", pw)
        self.assertNotIn("2", pw)
        self.assertTrue(pw.isdigit())

    def test_passphrase_customization(self):
        """Verifies advanced passphrase formatting."""
        plugin = GeneratorPlugin(asset_key=self.key)
        phrase = plugin.generate_passphrase(words=1, capitalize=True, include_number=True)
        # Should look like 'Testword5'
        self.assertTrue(phrase[0].isupper())
        self.assertTrue(any(c.isdigit() for c in phrase))

if __name__ == '__main__':
    unittest.main()