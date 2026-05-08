# koot/network/gateway/mtls_server.py
import ssl
import asyncio
import logging
import hashlib
from typing import Optional, Any

logger = logging.getLogger(__name__)

class ZeroTrustGateway:
    """
    mTLS Network Gateway for koot.
    Strictly requires and validates X.509 Client Certificates before allowing connection.
    Enforces authorization against the Shadow Ledger.
    """
    def __init__(self, host: str, port: int, ca_cert_path: str, server_cert_path: str, server_key_path: str, shadow_ledger: Any = None):
        self.host = host
        self.port = port
        self.ca_cert_path = ca_cert_path
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path
        self.shadow_ledger = shadow_ledger
        self.server: Optional[asyncio.AbstractServer] = None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Configures the SSL context to strictly require client certificates."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.server_cert_path, keyfile=self.server_key_path)
        
        # CORE COUNTERMEASURE: Require client certificate (mTLS)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=self.ca_cert_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles incoming validated connections and enforces Ledger boundaries."""
        addr = writer.get_extra_info('peername')
        ssl_obj = writer.get_extra_info('ssl_object')
        
        if not ssl_obj:
            logger.warning(f"Connection from {addr} dropped: No SSL context.")
            writer.close()
            await writer.wait_closed()
            return
            
        # Get the raw binary (DER) certificate to generate a clean, cryptographically secure hash
        der_cert = ssl_obj.getpeercert(binary_form=True)
        if not der_cert:
            logger.warning(f"Connection from {addr} dropped: No client certificate presented.")
            writer.close()
            await writer.wait_closed()
            return

        # Hash the DER certificate to look it up in the Shadow Ledger
        cert_hash = hashlib.sha256(der_cert).hexdigest()
        
        # Extract common name for logging context
        peer_cert = ssl_obj.getpeercert()
        subject = dict(x[0] for x in peer_cert.get('subject', ()))
        common_name = subject.get('commonName', 'Unknown')
        
        # --- Session 2: Context Extraction & Enforcement ---
        tenant_context = None
        if self.shadow_ledger:
            tenant_context = self.shadow_ledger.get_tenant(cert_hash)
            
            # Sub-user does not exist in the vault
            if not tenant_context:
                logger.warning(f"Intrusion attempt! Valid CA cert but hash {cert_hash[:8]}... not in Ledger. Dropping.")
                writer.close()
                await writer.wait_closed()
                return
                
            # Sub-user is locked
            if tenant_context.get('locked', False):
                logger.warning(f"Access denied! Tenant {tenant_context['tenant_id']} is locked. Dropping.")
                writer.close()
                await writer.wait_closed()
                return
                
            logger.info(f"Accepted connection. Tenant: {tenant_context['tenant_id']} (Permissions: {tenant_context['permissions']})")
        else:
            logger.info(f"Accepted authenticated mTLS connection from {addr} (NO LEDGER ATTACHED)")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                message = data.decode('utf-8')
                active_identity = tenant_context['tenant_id'] if tenant_context else common_name
                logger.debug(f"Received payload from {active_identity}: {message.strip()}")
                
                response = f"koot Zero-Trust Gateway: Acknowledged payload from '{active_identity}'\n"
                writer.write(response.encode('utf-8'))
                await writer.drain()
                
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.error(f"Error handling connection from {addr}: {e}")
        finally:
            logger.info(f"Closing connection to {addr}")
            writer.close()
            await writer.wait_closed()

    async def start(self):
        """Starts the mTLS listener."""
        ssl_context = self._create_ssl_context()
        self.server = await asyncio.start_server(
            self.handle_client, self.host, self.port, ssl=ssl_context
        )
        addrs = ', '.join(str(sock.getsockname()) for sock in self.server.sockets)
        logger.info(f"Zero-Trust mTLS Gateway actively enforcing on {addrs}")
        async with self.server:
            await self.server.serve_forever()