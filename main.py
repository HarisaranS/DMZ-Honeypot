import asyncio
import sys
from honeypot_core import HoneyPot
from services.http import HTTPService
from services.ssh import SSHService
from services.ftp import FTPService

async def main():
    # Initialize Core
    honey = HoneyPot()
    
    # Initialize Services
    # Note: We bind to non-privileged ports for safety in development (8080, 2222, 2121)
    http_service = HTTPService(honey, port=8080)
    ssh_service = SSHService(honey, port=2222)
    ftp_service = FTPService(honey, port=2121)

    honey.register_service(http_service.start())
    honey.register_service(ssh_service.start())
    honey.register_service(ftp_service.start())

    try:
        await honey.start()
    except KeyboardInterrupt:
        honey.stop()

if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
