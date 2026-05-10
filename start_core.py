import warnings
import logging

# SILENCE THE TPM NOISE: This must be at the very top
try:
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass

import asyncio
import os  # Added for absolute path resolution
from koot.network.ipc.server import LocalIPCGateway
from koot.network.gateway.mtls_server import ZeroTrustGateway
from koot.core.bus.registry import AdaptiveRegistry

# Set up logging so you can see what the core is doing
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Calculate the absolute path to the project root
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

async def boot_daemon():
    logging.info(f"Initializing Koot Adaptive Core in {PROJECT_ROOT}...")
    
    # 1. Initialize the Registry Bus (The Brain)
    registry = AdaptiveRegistry()
    
    # 2. Local Access (IPC)
    ipc_server = LocalIPCGateway(socket_path="/tmp/koot.sock", registry=registry)
    
    # 3. Remote Access (Zero-Trust mTLS)
    # Using os.path.join to ensure files are found regardless of where you run the command
    mtls_gateway = ZeroTrustGateway(
        host="0.0.0.0", 
        port=8443,
        ca_cert_path=os.path.join(PROJECT_ROOT, "certs/ca.crt"),
        server_cert_path=os.path.join(PROJECT_ROOT, "certs/server.crt"),
        server_key_path=os.path.join(PROJECT_ROOT, "certs/server.key"),
        shadow_ledger=None # Set to None; Ledger is attached AFTER vault unlock
    )

    # 4. Start both listeners
    logging.info("Starting IPC Server and Zero-Trust Gateway on port 8443...")
    await asyncio.gather(
        ipc_server.start(),
        mtls_gateway.start()
    )

if __name__ == "__main__":
    try:
        asyncio.run(boot_daemon())
    except KeyboardInterrupt:
        logging.info("Koot Core Daemon shutting down securely.")