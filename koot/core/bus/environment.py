import platform
import subprocess
import logging
import os

try:
    import psutil
except ImportError:
    psutil = None

class EnvironmentSensor:
    """
    The advanced sensory organ of the koot subsystem.
    Actively probes host hardware, cryptographic acceleration, and thermal/memory thresholds.
    """
    
    def __init__(self):
        self.logger = logging.getLogger("EnvironmentSensor")
        if not psutil:
            self.logger.warning("[!] psutil is missing. Falling back to static low-power defensive profiles.")

    def probe_system(self) -> dict:
        """
        Executes a deep hardware and system state probe.
        """
        metrics = {
            "os": platform.system(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "ram": self._get_memory_profile(),
            "cpu": self._get_cpu_profile(),
            "crypto_hardware": self._detect_crypto_acceleration(),
            "tpm_present": self._check_tpm_presence(),
        }
        
        # Calculate the engineered countermeasure profile based on the raw metrics
        metrics["security_enforcement_profile"] = self._calculate_enforcement_profile(metrics)
        return metrics

    def _get_memory_profile(self) -> dict:
        """Tracks critical RAM thresholds to prevent OOM crashes."""
        if not psutil:
            return {"available_mb": 1024, "total_mb": 2048, "percent_used": 50.0}
        
        mem = psutil.virtual_memory()
        return {
            "available_mb": mem.available // (1024 * 1024),
            "total_mb": mem.total // (1024 * 1024),
            "percent_used": mem.percent
        }

    def _get_cpu_profile(self) -> dict:
        """Detects compute power and potential thermal pressure."""
        if not psutil:
            return {"cores": 2, "load_avg": [0.0, 0.0, 0.0]}
            
        profile = {
            "cores_logical": psutil.cpu_count(logical=True),
            "cores_physical": psutil.cpu_count(logical=False),
        }
        
        # Load averages (Unix only)
        if hasattr(os, "getloadavg"):
            profile["load_avg"] = os.getloadavg()
            
        return profile

    def _detect_crypto_acceleration(self) -> dict:
        """
        Scans for hardware-level cryptography instructions (AES-NI, SHA, AVX2).
        Crucial for deciding between Quantum-Hybrid algorithms or lightweight fallbacks.
        """
        features = {"aes": False, "sha": False, "avx2": False}
        system = platform.system()

        try:
            if system == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read().lower()
                    features["aes"] = "aes" in cpuinfo
                    features["sha"] = "sha_ni" in cpuinfo or "sha1" in cpuinfo or "sha256" in cpuinfo
                    features["avx2"] = "avx2" in cpuinfo
            elif system == "Darwin":
                out = subprocess.check_output(["sysctl", "-a"]).decode().lower()
                features["aes"] = "aes" in out
                features["sha"] = "sha" in out
                features["avx2"] = "avx2" in out
        except Exception as e:
            self.logger.debug(f"Failed to probe CPU crypto instructions: {e}")
            
        return features

    def _check_tpm_presence(self) -> bool:
        """
        Checks for a physical or firmware TPM 2.0 module.
        Used later for the Machine Identity / AppRole zero-touch unlock.
        """
        if platform.system() == "Linux":
            return os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")
        elif platform.system() == "Windows":
            # Note: Checking TPM in Windows reliably often requires WMI/powershell, 
            # keeping this abstract for now to avoid freezing the boot sequence.
            pass 
        return False

    def _calculate_enforcement_profile(self, metrics: dict) -> dict:
        """
        [ENGINEERED COUNTERMEASURE: Hard Upper Limits & Predictive Ramp-Up]
        Computes strict operational boundaries based on hardware reality.
        """
        ram = metrics["ram"]["available_mb"]
        cpu = metrics["cpu"].get("cores_physical", 2)
        has_aes = metrics["crypto_hardware"]["aes"]

        profile = {
            "hardware_tier": "UNKNOWN",
            "argon2id_max_memory_kb": 65536,  # Safe default (64MB)
            "argon2id_max_parallelism": 1,
            "chunking_engine_max_kb": 16,     # Safe TCP-slow-start default
            "permit_hybrid_pqc": False        # Disable heavy Post-Quantum crypto on weak devices
        }

        # 1. Tier: HIGH-END (Desktop / Server)
        if ram > 4000 and cpu >= 4:
            profile["hardware_tier"] = "TIER_1_PERFORMANCE"
            profile["argon2id_max_memory_kb"] = 1048576  # Allow 1GB RAM for ultra-secure key derivation
            profile["argon2id_max_parallelism"] = cpu - 1
            profile["chunking_engine_max_kb"] = 64       # Full 64KB Merkle-Tree chunks
            profile["permit_hybrid_pqc"] = True

        # 2. Tier: MID-RANGE (Standard Laptop)
        elif ram > 2000 and cpu >= 2:
            profile["hardware_tier"] = "TIER_2_STANDARD"
            profile["argon2id_max_memory_kb"] = 262144   # 256MB RAM
            profile["argon2id_max_parallelism"] = 2
            profile["chunking_engine_max_kb"] = 32
            profile["permit_hybrid_pqc"] = True

        # 3. Tier: LOW-POWER (IoT, Raspberry Pi, Constrained VM)
        else:
            profile["hardware_tier"] = "TIER_3_CONSTRAINED"
            profile["argon2id_max_memory_kb"] = 32768    # Strict 32MB fallback to prevent OOM
            profile["argon2id_max_parallelism"] = 1
            profile["chunking_engine_max_kb"] = 16       # Force small stream processing
            profile["permit_hybrid_pqc"] = False         # Fall back to pure AES-256 (if hardware supports) or ChaCha20

        # Override: If no AES-NI hardware instruction, force chunking smaller to save CPU cycles
        if not has_aes:
            profile["chunking_engine_max_kb"] = min(profile["chunking_engine_max_kb"], 16)

        return profile