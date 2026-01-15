import asyncio
import logging

logger = logging.getLogger("HoneyPy.SSH")

class SSHService:
    def __init__(self, honeypot_core, port=2222):
        self.honeypot = honeypot_core
        self.port = port
        self.banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"

    async def handle_client(self, reader, writer):
        addr = writer.get_extra_info('peername')
        logger.info(f"New SSH connection from {addr}")

        try:
            # Send Banner
            writer.write(self.banner)
            await writer.drain()

            # Read client Version
            try:
                client_version = await asyncio.wait_for(reader.readuntil(b'\n'), timeout=10)
                client_version_str = client_version.decode().strip()
                self.honeypot.log_attack("SSH_HANDSHAKE", addr[0], addr[1], client_version_str)
            except asyncio.TimeoutError:
                pass # Just close if they don't respond

            # In a real SSH implementation (using paramiko/asyncssh), we would effectively negotiate keys
            # and then handle auth. Since this is "from scratch" simply to demonstrate the concept without 
            # heavy dependencies, we will detect the connection and just dump junk or hang to confuse scanners.
            # Building a full SSH protocol handshake from scratch is extremely complex (crypto etc).
            # For a 'worthwhile logic' project, we can simulate the *TCP* behavior or use a library.
            # To keep it 'from scratch' but functional, we'll log the attempt and close.
            
            # NOTE: For a more advanced version, we would use 'asyncssh' library to accept passwords. 
            # But let's stick to raw socket interaction for the 'learning' aspect unless user requested libs.
            # We'll log the interaction.
            
            pass 

        except Exception as e:
            logger.error(f"Error handling SSH connection: {e}")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass

    async def start(self):
        server = await asyncio.start_server(
            self.handle_client, '0.0.0.0', self.port
        )
        logger.info(f"SSH Service listening on port {self.port}")
        async with server:
            await server.serve_forever()
