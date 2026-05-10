import asyncio
import logging
from koot.network.ipc.server import LocalIPCGateway
from koot.core.bus.registry import AdaptiveRegistry

# Set up logging so you can see what the core is doing
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

async def boot_daemon():
    logging.info("Initializing Koot Adaptive Core...")
    
    # 1. Initialize the Registry Bus (The Brain)
    registry = AdaptiveRegistry()
    
    # 2. Initialize the IPC Gateway (The Ears)
    ipc_server = LocalIPCGateway(socket_path="/tmp/koot.sock", registry=registry)
    
    # 3. Start listening forever
    await ipc_server.start()

if __name__ == "__main__":
    try:
        asyncio.run(boot_daemon())
    except KeyboardInterrupt:
        logging.info("Koot Core Daemon shutting down securely.")