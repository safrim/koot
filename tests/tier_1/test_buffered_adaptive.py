import pytest
import os
from unittest.mock import patch, MagicMock, mock_open
from koot.storage.chunking.buffered_adaptive import BufferedAdaptiveChunker

class TestBufferedAdaptiveChunker:
    
    @patch('psutil.virtual_memory')
    def test_evaluate_hardware_abundant_ram(self, mock_vm):
        """Test that abundant RAM (>2GB) allocates high-speed 1MB physical reads."""
        mock_mem = MagicMock()
        mock_mem.available = 8 * 1024 * 1024 * 1024  # 8 GB available
        mock_vm.return_value = mock_mem

        chunker = BufferedAdaptiveChunker()
        chunker._evaluate_hardware()
        assert chunker.current_physical_size == 1048576, "Should allocate 1MB reads for abundant RAM"

    @patch('psutil.virtual_memory')
    def test_evaluate_hardware_constrained_ram(self, mock_vm):
        """Test that constrained RAM (<2GB) scales physical reads to 64KB."""
        mock_mem = MagicMock()
        mock_mem.available = 1024 * 1024 * 1024  # 1 GB available
        mock_vm.return_value = mock_mem

        chunker = BufferedAdaptiveChunker()
        # Force it to a different size first to prove the evaluation changes it
        chunker.current_physical_size = 16384 
        chunker._evaluate_hardware()
        assert chunker.current_physical_size == 65536, "Should allocate 64KB reads for constrained RAM"

    @patch('psutil.virtual_memory')
    def test_evaluate_hardware_critical_ram(self, mock_vm):
        """Test that critical RAM (<512MB) aggressively throttles to 16KB physical reads."""
        mock_mem = MagicMock()
        mock_mem.available = 256 * 1024 * 1024  # 256 MB available
        mock_vm.return_value = mock_mem

        chunker = BufferedAdaptiveChunker()
        chunker.current_physical_size = 1048576
        chunker._evaluate_hardware()
        assert chunker.current_physical_size == 16384, "Should throttle to 16KB reads for critical RAM"

    @patch('psutil.virtual_memory', side_effect=Exception("Telemetry missing"))
    def test_evaluate_hardware_sensor_failure_fallback(self, mock_vm):
        """Test that a sensor failure defaults to a highly defensive 16KB read limit."""
        chunker = BufferedAdaptiveChunker()
        chunker.current_physical_size = 1048576
        chunker._evaluate_hardware()
        assert chunker.current_physical_size == 16384, "Should fallback to 16KB reads upon sensor failure"

    @patch('psutil.virtual_memory')
    def test_process_stream_yields_strict_logical_boundaries(self, mock_vm):
        """
        CRITICAL TEST: Ensures that regardless of the hardware-dictated physical read size, 
        the system strictly yields exactly 64KB logical chunks for the Merkle tree.
        """
        # Simulate Abundant RAM (Reads 1MB at a time physically)
        mock_mem = MagicMock()
        mock_mem.available = 8 * 1024 * 1024 * 1024  
        mock_vm.return_value = mock_mem

        # Mock a file with exactly 100KB of random data (102,400 bytes)
        mock_file_data = os.urandom(102400)
        chunker = BufferedAdaptiveChunker(logical_chunk_size=65536)
        
        # Patch the built-in open function to return our mock file data
        with patch('builtins.open', mock_open(read_data=mock_file_data)):
            chunks = list(chunker.process_stream("dummy_vault_payload.bin"))
            
        # 100KB total should be split into exactly two yields:
        # Yield 1: 64KB (65,536 bytes)
        # Yield 2: ~36KB (36,864 bytes - the trailing remaining data)
        assert len(chunks) == 2, "Stream processor should yield exactly 2 chunks for 100KB of data"
        assert len(chunks[0]) == 65536, "First chunk MUST be exactly 64KB to maintain Merkle Tree integrity"
        assert len(chunks[1]) == 36864, "Second chunk should contain the exact remaining trailing bytes"