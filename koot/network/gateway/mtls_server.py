# koot/network/gateway/mtls_server.py
import ssl
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class ZeroTrustGateway:
    """
    mTLS Network Gateway for koot.
    Strictly requires and validates X.509 Client Certificates before allowing connection.
    """
    def __init__(self, host: str, port: int, ca_cert_path: str, server_cert_path: str, server_key_path: str):
        self.host = host
        self.port = port
        self.ca_cert_path = ca_cert_path
        self.server_cert_path = server_cert_path
        self.server_key_path = server_key_path
        self.server: Optional[asyncio.AbstractServer] = None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Configures the SSL context to strictly require client certificates."""
        # Create context specifically for Server usage, requiring client auth
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load the Server's certificate and private key
        context.load_cert_chain(certfile=self.server_cert_path, keyfile=self.server_key_path)
        
        # CORE COUNTERMEASURE: Require client certificate (mTLS)
        context.verify_mode = ssl.CERT_REQUIRED
        
        # Load the CA certificate used to verify the client's certificate
        context.load_verify_locations(cafile=self.ca_cert_path)
        
        # Disable older, insecure protocols (Enforce TLS 1.2 or TLS 1.3)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        return context

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handles incoming validated connections."""
        peer_cert = writer.get_extra_info('peercert')
        addr = writer.get_extra_info('peername')
        
        if not peer_cert:
            # Fallback check (verify_mode=CERT_REQUIRED usually prevents reaching this point)
            logger.warning(f"Connection from {addr} dropped: No client certificate presented.")
            writer.close()
            await writer.wait_closed()
            return
            
        # Extract metadata from the validated certificate
        subject = dict(x[0] for x in peer_cert.get('subject', ()))
        common_name = subject.get('commonName', 'Unknown')
        
        logger.info(f"Accepted authenticated mTLS connection from {addr} (Client CN: {common_name})")
        
        try:
            while True:
                data = await reader.read(1024)
                if not data:
                    break
                
                message = data.decode('utf-8')
                logger.debug(f"Received payload from {common_name}: {message.strip()}")
                
                # In a full implementation, this routes the payload to the koot registry bus
                response = f"koot Zero-Trust Gateway: Acknowledged payload from '{common_name}'\n"
                writer.write(response.encode('utf-8'))
                await writer.drain()
                
        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            logger.error(f"Error handling connection from {common_name}: {e}")
        finally:
            logger.info(f"Closing connection to {common_name}")
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