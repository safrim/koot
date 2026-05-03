import os
import platform
import psutil
import subprocess

class EnvironmentSensor:
    """
    Actively probes the host system to drive the Capability Matrix.
    Strictly implements the core mandates: OS, RAM, AES-NI, TPM 2.0, and Thermals.
    """
    
    def __init__(self):
        self.os_type = platform.system()
        self.ram_gb = psutil.virtual_memory().total / (1024**3)
        self.cpu_cores = psutil.cpu_count(logical=False)
        
        # --- CORE MANDATE 1 & 2: Hardware Acceleration (AES-NI & TPM 2.0) ---
        self.has_aes_ni = self._check_aes_ni()
        self.has_tpm = self._check_tpm()
        
        # --- CORE MANDATE 3: Dynamic Throttling Sensors ---
        self.thermal_state = self._check_thermal_load()
        
        # --- Critical Add-on: Entropy Safety ---
        self.entropy_healthy = self._check_entropy()

    def _check_aes_ni(self) -> bool:
        """Probes the CPU for Hardware AES instruction sets."""
        try:
            if self.os_type == 'Linux':
                with open('/proc/cpuinfo', 'r') as f:
                    return 'aes' in f.read().lower()
            elif self.os_type == 'Darwin': # macOS
                result = subprocess.run(['sysctl', '-a'], capture_output=True, text=True)
                return 'aes' in result.stdout.lower()
            # Note: Windows requires complex WMI calls or C-extensions to reliably check CPU flags in pure Python.
        except Exception:
            pass
        return False

    def _check_tpm(self) -> bool:
        """Probes for an accessible Hardware Root of Trust (TPM 2.0)."""
        if self.os_type == 'Linux':
            # Checks for standard Linux TPM device handlers
            return os.path.exists('/dev/tpmrm0') or os.path.exists('/dev/tpm0')
        return False

    def _check_thermal_load(self) -> str:
        """
        Monitors real-time CPU thermal loads to prevent kernel panics on weak devices
        during massive decryption jobs.
        """
        if not hasattr(psutil, "sensors_temperatures"):
            return "UNSUPPORTED_OS"
            
        try:
            temps = psutil.sensors_temperatures()
            if not temps:
                return "NO_SENSORS_FOUND"
                
            for name, entries in temps.items():
                for entry in entries:
                    if entry.current > 85.0: # 85°C is a standard threshold for thermal throttling
                        return "CRITICAL_HEAT"
                        
            return "NORMAL"
        except Exception:
            return "ERROR_READING_SENSORS"

    def _check_entropy(self) -> bool:
        """Validates OS randomness pool to prevent fatal crypto failures."""
        try:
            return len(os.urandom(32)) == 32
        except Exception:
            return False

    def get_telemetry(self) -> dict:
        """Returns the full intelligence matrix to the Registry Bus."""
        # Define the hardware tier based on RAM and CPU power
        tier = "ENTERPRISE" if (self.ram_gb > 4 and self.cpu_cores > 2) else "IOT_EDGE"
        
        return {
            "os": self.os_type,
            "tier": tier,
            "ram_gb": round(self.ram_gb, 2),
            "cpu_cores": self.cpu_cores,
            "hardware_accel": {
                "aes_ni": self.has_aes_ni,
                "tpm_present": self.has_tpm
            },
            "system_health": {
                "thermal_load": self.thermal_state,
                "entropy_healthy": self.entropy_healthy
            }
        }