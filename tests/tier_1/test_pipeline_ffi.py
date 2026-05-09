import unittest
from unittest.mock import patch, MagicMock
import koot.identity.derivation.pipeline as pipeline_module
from koot.identity.derivation.pipeline import EntropyPipeline

class TestEntropyPipelineFFI(unittest.TestCase):
    
    def setUp(self):
        # Force the module to think the enclave is available for testing
        pipeline_module.ENCLAVE_AVAILABLE = True
        
        # Mock the loaded C shared library
        pipeline_module._enclave_lib = MagicMock()
        
        # Mock the C function to return a dummy pointer ID "999" on allocation
        pipeline_module._enclave_lib.allocate_secure_key.return_value = 999
        pipeline_module._enclave_lib.destroy_secure_key.return_value = None

    @patch('gc.collect')
    def test_enclave_integration_and_memory_sweep(self, mock_gc):
        """
        Proves that derive_and_lock_key sends the key to the C-Enclave, 
        stores only the pointer ID, and triggers a garbage collection sweep.
        """
        pipeline = EntropyPipeline()
        password = "ZeroTrustMasterPassword123!"
        
        ptr_id, salt = pipeline.derive_and_lock_key(password)
        
        # Verify the C-Enclave was called to allocate the key
        pipeline_module._enclave_lib.allocate_secure_key.assert_called_once()
        
        # Verify the Python object only holds the integer ID referencing the secure memory
        self.assertEqual(ptr_id, 999)
        self.assertEqual(pipeline.active_key_id, 999)
        self.assertEqual(len(salt), 16)
        
        # Verify Python's garbage collector was explicitly triggered to sweep the plaintext from heap memory
        mock_gc.assert_called()

    def test_go_cold_memory_destruction(self):
        """
        Proves that go_cold() successfully triggers the C-Enclave to destroy 
        the memory pointer and nullifies the Python reference.
        """
        pipeline = EntropyPipeline()
        pipeline.derive_and_lock_key("SomeSecretPassword")
        
        self.assertIsNotNone(pipeline.active_key_id)
        
        # Trigger the lock
        pipeline.go_cold()
        
        # Verify the C-Enclave destruction method was invoked with the correct pointer ID
        pipeline_module._enclave_lib.destroy_secure_key.assert_called_once_with(999)
        
        # Verify Python dropped the pointer reference
        self.assertIsNone(pipeline.active_key_id)

    def test_ffi_unavailable_graceful_denial(self):
        """
        Proves that if the C-Enclave library cannot be loaded, the pipeline 
        refuses to derive the key in standard RAM and raises a RuntimeError.
        """
        pipeline_module.ENCLAVE_AVAILABLE = False
        pipeline = EntropyPipeline()
        
        with self.assertRaisesRegex(RuntimeError, "CRITICAL: C-Enclave memory lockdown is unavailable"):
            pipeline.derive_and_lock_key("TestPassword")

if __name__ == '__main__':
    unittest.main()