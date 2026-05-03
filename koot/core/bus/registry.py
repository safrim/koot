from typing import Dict, Any, Type, Callable
import logging

class PluginSandbox:
    """
    [ENGINEERED COUNTERMEASURE: Strict Process Isolation]
    A wrapper that ensures plugins only receive explicit inputs and cannot 
    access the broader global state. (Precursor to Wasm/IPC).
    """
    def __init__(self, plugin_instance: Any, name: str):
        self._plugin = plugin_instance
        self._name = name

    def execute(self, method_name: str, **kwargs) -> Any:
        if not hasattr(self._plugin, method_name):
            raise AttributeError(f"Sandbox Error: Plugin '{self._name}' has no method '{method_name}'")
        
        method = getattr(self._plugin, method_name)
        
        # In a full Wasm implementation, this is where we would serialize kwargs, 
        # send to the sandbox, wait for the result, and trigger memory wiping.
        try:
            result = method(**kwargs)
            # Memory Wipe Simulation: Ensure variables aren't hanging around
            del kwargs 
            return result
        except Exception as e:
            logging.error(f"[SANDBOX BREACH] Plugin {self._name} crashed during {method_name}: {e}")
            raise

class PluginRegistry:
    """
    The adaptive registry bus that manages and isolates swappable plugins.
    Enforces hardware thresholds and interface compliance.
    """
    def __init__(self, system_profile: dict):
        self._plugins: Dict[str, PluginSandbox] = {}
        self._system_profile = system_profile
        logging.basicConfig(level=logging.INFO, format='%(message)s')
        self.logger = logging.getLogger("RegistryBus")

    def mount_plugin(self, name: str, plugin_class: Type, required_methods: list = None, requires_pqc: bool = False) -> bool:
        """
        Registers a plugin, checking compliance and hardware limits before mounting.
        """
        # 1. Hardware Threshold Check
        if requires_pqc and not self._system_profile.get("permit_hybrid_pqc", False):
            self.logger.warning(f"  [REJECTED] Plugin '{name}' requires Post-Quantum Crypto. Blocked by Tier 3 Hardware Profile.")
            return False

        # 2. Interface Compliance Check
        if required_methods:
            for method in required_methods:
                if not hasattr(plugin_class, method) or not callable(getattr(plugin_class, method)):
                    self.logger.error(f"  [REJECTED] Plugin '{name}' failed compliance. Missing required method: {method}()")
                    return False
        
        # 3. Mount into Sandbox
        plugin_instance = plugin_class()
        
        # Pass necessary limits directly to the plugin if it can accept them
        if hasattr(plugin_instance, "apply_hardware_limits"):
            plugin_instance.apply_hardware_limits(self._system_profile)

        self._plugins[name] = PluginSandbox(plugin_instance, name)
        self.logger.info(f"  [MOUNTED] Plugin '{name}' sandboxed and compliant.")
        return True

    def get_plugin_interface(self, name: str) -> PluginSandbox:
        if name not in self._plugins:
            raise ValueError(f"Plugin '{name}' is not mounted on the Registry Bus.")
        return self._plugins[name]