import uuid
import multiprocessing
import logging
from .environment import EnvironmentSensor
# from .contracts import ContractEnforcer  # Assuming we implement this later

# Configure basic timely notifications
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

class AdaptiveRegistry:
    """
    The Central Nervous System of koot.
    Handles strict isolation, intelligent hardware routing, and manual overrides.
    """
    
    def __init__(self, override_matrix: dict = None):
        """
        Initializes the bus.
        :param override_matrix: A dictionary of admin-forced settings (e.g., {"force_software_aes": True})
        """
        self.sensor = EnvironmentSensor()
        self.telemetry = self.sensor.get_telemetry()
        self.plugins = {}
        
        # CORE MANDATE: The Manual Override Matrix
        self.overrides = override_matrix or {}
        
        self._notify_system_state()

    def _notify_system_state(self):
        """CORE MANDATE: Clear & Timely Notifications regarding System Health."""
        logging.info(f"System Boot: {self.telemetry['os']} | Tier: {self.telemetry['tier']}")
        
        if not self.telemetry['system_health']['entropy_healthy']:
            logging.warning("CRITICAL: OS Entropy is low. Key generation may be unsafe.")
            
        if self.telemetry['system_health']['thermal_load'] == "CRITICAL_HEAT":
            logging.warning("THERMAL ALARM: CPU is overheating. System will throttle heavy tasks.")

    def resolve_capability(self, domain: str) -> str:
        """
        CORE MANDATE: Intelligent Automation combined with Manual Overrides.
        Determines exactly which version of a plugin to load based on hardware,
        UNLESS an admin override is active.
        """
        # Example 1: Resolving Cryptography
        if domain == "crypto":
            # 1. Check for Manual Override first
            if self.overrides.get("force_software_crypto"):
                logging.info("[OVERRIDE] Forcing Software Crypto despite hardware capabilities.")
                return "crypto.fallback"
            
            # 2. Intelligent Automation
            if self.telemetry['hardware_accel']['aes_ni']:
                logging.info("[AUTO] Hardware AES-NI detected. Routing to Accelerated Crypto.")
                return "crypto.accelerated"
            else:
                logging.info("[AUTO] No AES-NI detected. Routing to Fallback Crypto.")
                return "crypto.fallback"

        # Example 2: Resolving Data Streaming (Thermal Throttling)
        if domain == "streaming":
            if self.overrides.get("ignore_thermals"):
                logging.warning("[OVERRIDE] Thermal throttling disabled. Proceeding at maximum speed.")
                return "stream.max_throughput"
                
            if self.telemetry['system_health']['thermal_load'] == "CRITICAL_HEAT":
                logging.info("[AUTO] Thermal limit reached. Routing to Throttled Streamer.")
                return "stream.throttled"
            
            return "stream.max_throughput"

        return "unknown.plugin"

    def mount_plugin(self, name: str, plugin_module):
        """
        Mounts the validated plugin into a strictly isolated process.
        """
        # (Contract enforcement would happen here)
        
        try:
            parent_conn, child_conn = multiprocessing.Pipe()
            
            process = multiprocessing.Process(
                target=self._actor_loop, 
                args=(child_conn, plugin_module),
                daemon=True
            )
            process.start()
            
            self.plugins[name] = {
                "pipe": parent_conn,
                "process": process
            }
            logging.info(f"Mounted isolated capability: '{name}' (PID: {process.pid})")
        except Exception as e:
            logging.error(f"Failed to mount capability '{name}': {e}")

    def _actor_loop(self, pipe, plugin_module):
        """The isolated execution field for the plugin (Zero-Shared Memory)."""
        while True:
            try:
               msg = pipe.recv()
               action = msg.get("action")
               kwargs = msg.get("kwargs", {})
               
               func = getattr(plugin_module, action)
               result = func(**kwargs)
               
               pipe.send({"status": "OK", "data": result})
            except Exception as e:
               pipe.send({"status": "ERROR", "error": str(e)})

    def dispatch(self, plugin_name: str, action: str, **kwargs):
        """Commands the isolated plugin and returns the result."""
        if plugin_name not in self.plugins:
            raise ValueError(f"Capability '{plugin_name}' is offline.")
            
        pipe = self.plugins[plugin_name]["pipe"]
        pipe.send({"action": action, "kwargs": kwargs})
        
        response = pipe.recv()
        if response["status"] == "ERROR":
            raise Exception(f"Plugin Panic ({plugin_name}): {response['error']}")
            
        return response["data"]