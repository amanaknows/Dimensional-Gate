import asyncio
import json
import logging
import os
import platform
import signal
import subprocess
import time
from datetime import datetime
from hashlib import sha256
from typing import Dict, List, Optional, Set

import aiohttp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from scapy.all import sniff, IP, Raw
except ImportError:
    sniff = None
    IP = None
    Raw = None
    print("[WARNING] Scapy not installed. Packet capture disabled.")

# === CONFIG ===
ANGELNET_API_BASE = "https://api.angelnet.example"  # TODO: replace with real API endpoint
ANGELNET_NOTIFICATION_API = ANGELNET_API_BASE + "/notify"
ANGELNET_COMMAND_EXEC_API = ANGELNET_API_BASE + "/exec"  # Secure bash command execution endpoint

ALLOWED_CLEARANCES = {"A", "AA", "AAA"}  # S5 exclusive clearance set (excludes S3)
ENCRYPTION_KEY = AESGCM.generate_key(bit_length=128)
aesgcm = AESGCM(ENCRYPTION_KEY)
LOG_FILE_PATH = "nahms_event_log_s5.jsonl"
SNAPSHOT_DIR = "./snapshots_s5"

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("nahms_debug_s5.log")]
)

shutdown_flag = False

def signal_handler(signum, frame):
    global shutdown_flag
    logging.info("Shutdown signal received.")
    shutdown_flag = True


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

class AngelNETAPI:
    def __init__(self):
        self.session = aiohttp.ClientSession()

    async def send_notification(self, message: str):
        payload = {"message": message, "timestamp": time.time()}
        try:
            async with self.session.post(
                ANGELNET_NOTIFICATION_API, json=payload, timeout=5
            ) as resp:
                if resp.status == 200:
                    logging.info("AngelNET notification sent.")
                else:
                    logging.warning(f"Notification failed: HTTP {resp.status}")
        except Exception as e:
            logging.error(f"Notification exception: {e}")

    async def run_bash_command(self, command: str) -> Dict[str, str]:
        payload = {"command": command, "timestamp": time.time()}
        try:
            async with self.session.post(
                ANGELNET_COMMAND_EXEC_API, json=payload, timeout=10
            ) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    logging.info(f"Bash command executed: {command}")
                    return result
                else:
                    logging.warning(f"Bash command failed: HTTP {resp.status}")
                    return {"error": f"HTTP {resp.status}"}
        except Exception as e:
            logging.error(f"Bash command exception: {e}")
            return {"error": str(e)}

    async def check_master_clearance(self, user_id: str) -> bool:
        """
        Query AngelNET Sith S5 master node for clearance verification.
        Returns True if user has master clearance, else False.
        """
        # Simulated API endpoint and payload - replace with real endpoint
        master_check_api = ANGELNET_API_BASE + "/sith/s5/clearance"
        payload = {"user_id": user_id, "timestamp": time.time()}
        try:
            async with self.session.post(master_check_api, json=payload, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    authorized = data.get("authorized", False)
                    if authorized:
                        logging.info(f"Master clearance granted for user {user_id}")
                    else:
                        logging.warning(f"Master clearance denied for user {user_id}")
                    return authorized
                else:
                    logging.warning(f"Master clearance check failed HTTP {resp.status}")
                    return False
        except Exception as e:
            logging.error(f"Master clearance check exception: {e}")
            return False

    async def close(self):
        await self.session.close()


# === Main NAHMS S5 loop with Master Clearance ===
async def nahms_main_loop(user_id: str, clearance: str, dry_run=False):
    logger = EventLogger(LOG_FILE_PATH)
    api = AngelNETAPI()

    # First: Master clearance check at AngelNET Sith S5 top chain
    has_master_clearance = await api.check_master_clearance(user_id)
    if not has_master_clearance:
        logging.error(f"User {user_id} lacks AngelNET Sith S5 master clearance. Access denied.")
        await api.close()
        logger.close()
        return

    ggu = GateGovernanceUnit(logger, api)

    # Secondary authentication for S5 clearance level
    if not ggu.authenticate_user(user_id, clearance):
        logging.error("Authentication failed, exiting.")
        await api.close()
        logger.close()
        return

    # ...[rest of the existing main loop unchanged]...

    ggu.add_attack_pattern({"name": "SQL Injection", "signature": "UNION SELECT"})
    ggu.add_attack_pattern({"name": "XSS", "signature": "<script>"})

    ggu.open_port(22)
    ggu.open_port(443)

    packet_task = asyncio.create_task(packet_capture_loop(ggu))

    try:
        while not shutdown_flag:
            entity_id = "entity_42"
            entity_data = {"behavior_score": 0.85 + 0.1 * (time.time() % 2)}

            if ggu.detect_malicious_entity(entity_id, entity_data):
                logging.warning(f"Entity {entity_id} quarantined due to behavior.")

            suspicious_ports = ggu.monitor_ports()
            if suspicious_ports:
                logging.warning(f"Suspicious ports: {suspicious_ports}")

            await ggu.quantum_synthetic_resource_check()

            if int(time.time()) % 300 == 0:
                ggu.take_snapshot()
                await ggu.alpha_beta_testing_and_recovery()

            if dry_run:
                logging.info("Dry run enabled - no active network changes.")

            if int(time.time()) % 60 == 0:
                cmd_result = await ggu.run_bash_via_angelnet("uname -a")
                logging.info(f"Bash command result: {cmd_result}")

            await asyncio.sleep(5)

    except Exception as e:
        logging.error(f"Main loop error: {e}")
    finally:
        logging.info("Shutting down NAHMS S5...")
        packet_task.cancel()
        await api.close()
        logger.close()


# === CLI Entrypoint ===
if __name__ == "__main__":
    import sys

    user = sys.argv[1] if len(sys.argv) > 1 else "guest"
    clearance = sys.argv[2] if len(sys.argv) > 2 else "X"
    dry_run_flag = "--dry-run" in sys.argv

    asyncio.run(nahms_main_loop(user, clearance, dry_run=dry_run_flag))
