import asyncio
import logging
import json
from datetime import datetime
import os
import signal

# Configure logging
LOG_DIR = "logs"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"{LOG_DIR}/honeypot.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("HoneyPy")

class HoneyPot:
    def __init__(self):
        self.services = []
        self.running = True

    def log_attack(self, service_name, ip, port, payload):
        event = {
            "timestamp": datetime.now().isoformat(),
            "service": service_name,
            "attacker_ip": ip,
            "attacker_port": port,
            "payload": payload
        }
        # Log purely to JSON for easy parsing later
        with open(f"{LOG_DIR}/attacks.json", "a") as f:
            f.write(json.dumps(event) + "\n")
        
        logger.warning(f"ATTACK DETECTED [{service_name}] from {ip}:{port} | {payload[:50]}...")

    def register_service(self, service_coroutine):
        self.services.append(service_coroutine)

    async def start(self):
        logger.info("HoneyPy starting up...")
        await asyncio.gather(*self.services)

    def stop(self):
        logger.info("HoneyPy shutting down...")
        self.running = False

# Import services dynamically or statically here
# In a larger app, we'd load plugins. For this scratch project, we'll pass the instance to services.
